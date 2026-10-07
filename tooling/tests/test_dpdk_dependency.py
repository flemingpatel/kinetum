"""Tests for the exact source-produced Kinetum DPDK dependency boundary."""

import hashlib
import io
import json
from pathlib import Path
import shlex
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

from tooling.environment import build_kinetum_dpdk


class DpdkBuilderIdentityTest(unittest.TestCase):
    """Validate the interpreter that performs the exact native build."""

    def test_builder_requires_exact_python_and_pyelftools(self):
        """Python and pyelftools mismatches reject at the builder boundary."""
        policy = {"builder": {
            "os_id": "ubuntu",
            "os_version": "24.04",
            "cc_version": "13.3.0",
            "ld_version": "GNU ld (GNU Binutils for Ubuntu) 2.42",
            "ar_version": "GNU ar (GNU Binutils for Ubuntu) 2.42",
            "as_version": "GNU assembler (GNU Binutils for Ubuntu) 2.42",
            "ninja_version": "1.11.1",
            "pkg_config_version": "1.8.1",
            "python_version": "3.12.3",
            "pyelftools_version": "0.30",
            "source_date_epoch": 0,
        }}
        outputs = {
            ("cc", "-dumpfullversion", "-dumpversion"): "13.3.0",
            ("ld", "--version"): "GNU ld (GNU Binutils for Ubuntu) 2.42",
            ("ar", "--version"): "GNU ar (GNU Binutils for Ubuntu) 2.42",
            ("as", "--version"): "GNU assembler (GNU Binutils for Ubuntu) 2.42",
            ("ninja", "--version"): "1.11.1",
            ("pkg-config", "--version"): "1.8.1",
        }
        elf_probe = (
            "/usr/bin/python3", "-I", "-B", "-c",
            "import elftools; print(elftools.__version__)",
        )

        def probe(arguments, **kwargs):
            """Return independently authored output for each exact invocation."""
            self.assertEqual(
                kwargs["env"],
                {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"},
            )
            return subprocess.CompletedProcess(
                arguments, 0, stdout=outputs[tuple(arguments)], stderr=""
            )

        with (
            mock.patch.object(build_kinetum_dpdk, "parse_os_release", return_value={
                "ID": "ubuntu", "VERSION_ID": "24.04",
            }),
            mock.patch.object(build_kinetum_dpdk.subprocess, "run", side_effect=probe),
            mock.patch.object(build_kinetum_dpdk.sys, "executable", "/usr/bin/python3"),
            mock.patch.object(
                build_kinetum_dpdk.shutil, "which", return_value="/usr/bin/tool"
            ) as tool_lookup,
            mock.patch.object(build_kinetum_dpdk.platform, "python_version") as python_version,
            mock.patch.dict(build_kinetum_dpdk.os.environ, {
                "PATH": "/untrusted/tools",
                "LC_ALL": "untrusted-locale",
                "LD_PRELOAD": "/untrusted/loader.so",
            }),
        ):
            for python, elftools, diagnostic in (
                ("3.12.3", "0.30", None),
                ("3.12.4", "0.30", "builder python_version mismatch"),
                ("3.12.3", "0.31", "builder pyelftools_version mismatch"),
            ):
                with self.subTest(python=python, elftools=elftools):
                    python_version.return_value = python
                    outputs[elf_probe] = elftools
                    if diagnostic is None:
                        build_kinetum_dpdk.validate_builder(policy)
                    else:
                        with self.assertRaisesRegex(build_kinetum_dpdk.ProducerError, diagnostic):
                            build_kinetum_dpdk.validate_builder(policy)
            self.assertEqual(
                {call.kwargs.get("path") for call in tool_lookup.call_args_list},
                {"/usr/bin:/bin"},
            )

    def test_meson_python_bindings_preserve_the_selected_interpreter(self):
        """Both Meson lookups use the admitted interpreter without rediscovery."""
        with tempfile.TemporaryDirectory() as temporary:
            native_file = Path(temporary) / "native.ini"
            with mock.patch.object(
                build_kinetum_dpdk.sys, "executable", "/exact toolchain/bin/python3"
            ):
                build_kinetum_dpdk.write_meson_native_file(native_file)
            self.assertEqual(
                native_file.read_text(encoding="utf-8"),
                "[binaries]\npython = '/exact toolchain/bin/python3'\npython3 = python\n",
            )
            for interpreter in (
                "relative/python3",
                "/toolchain's/bin/python3",
                "/toolchain\\path/bin/python3",
                "/toolchain\npath/bin/python3",
                "/toolchain/@DIRNAME@/python3",
                "/toolchain/@GLOBAL_SOURCE_ROOT@/python3",
            ):
                with (
                    self.subTest(interpreter=interpreter),
                    mock.patch.object(build_kinetum_dpdk.sys, "executable", interpreter),
                    self.assertRaisesRegex(build_kinetum_dpdk.ProducerError, "cannot be represented"),
                ):
                    build_kinetum_dpdk.write_meson_native_file(native_file)
                self.assertEqual(
                    native_file.read_text(encoding="utf-8"),
                    "[binaries]\npython = '/exact toolchain/bin/python3'\npython3 = python\n",
                )


class DpdkDependencyProducerTest(unittest.TestCase):
    """Validate producer isolation and benchmark dependency provenance."""

    def test_source_patch_is_required_and_changes_dependency_policy_identity(self):
        """Changed patch bytes invalidate prior packages; an absent patch prevents production."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in build_kinetum_dpdk.POLICY_FILES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}\n", encoding="ascii")
            (root / "third_party/dpdk/dependency_manifest.json").write_text(
                '{"schema_version":1}\n', encoding="ascii"
            )
            source_patch = root / build_kinetum_dpdk.DPDK_SOURCE_PATCH
            source_patch.write_text("first patch\n", encoding="ascii")
            _, original_identity = build_kinetum_dpdk.load_policy(root)
            source_patch.write_text("changed patch\n", encoding="ascii")
            _, changed_identity = build_kinetum_dpdk.load_policy(root)
            self.assertNotEqual(changed_identity, original_identity)
            source_patch.unlink()
            with self.assertRaisesRegex(build_kinetum_dpdk.ProducerError, "policy input is missing"):
                build_kinetum_dpdk.load_policy(root)

    def test_build_json_admission_is_bounded_and_unambiguous(self):
        """Policy and producer JSON reject ambiguous or unbounded documents."""
        parser = build_kinetum_dpdk._parse_json_object  # pylint: disable=protected-access
        self.assertEqual(
            parser(b'{"nested":{"items":[1,"ok",true]}}', "fixture"),
            {"nested": {"items": [1, "ok", True]}},
        )
        malformed = (
            b'{"key":1,"key":2}',
            b'{"nested":{"key":1,"key":2}}',
            b'{"value":NaN}',
            b'{"value":Infinity}',
            b'{"value":-Infinity}',
            b'{"value":1e999}',
            b'{"\\ud800":"value"}',
            b'{"value":"\\udfff"}',
            b'{"value":"\xff"}',
        )
        for raw in malformed:
            with self.subTest(raw=raw), self.assertRaises(
                build_kinetum_dpdk.ProducerError
            ):
                parser(raw, "fixture")
        with self.assertRaises(build_kinetum_dpdk.ProducerError):
            parser(b"[]", "fixture")

        prefix = b'{"value":"'
        suffix = b'"}'
        exact = prefix + b"x" * (
            build_kinetum_dpdk.BUILD_JSON_LIMIT_BYTES
            - len(prefix)
            - len(suffix)
        ) + suffix
        self.assertEqual(len(exact), build_kinetum_dpdk.BUILD_JSON_LIMIT_BYTES)
        self.assertEqual(len(parser(exact, "fixture")["value"]), len(exact) - 12)
        with self.assertRaises(build_kinetum_dpdk.ProducerError):
            parser(exact + b" ", "fixture")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in build_kinetum_dpdk.POLICY_FILES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}\n", encoding="ascii")
            manifest = root / "third_party/dpdk/dependency_manifest.json"
            manifest.write_text('{"schema_version":1}\n', encoding="ascii")
            self.assertEqual(build_kinetum_dpdk.load_policy(root)[0], {"schema_version": 1})
            for version in (None, True, 1.0, "1", 0, 2):
                with self.subTest(schema_version=version):
                    manifest.write_text(json.dumps({"schema_version": version}), encoding="ascii")
                    with self.assertRaisesRegex(build_kinetum_dpdk.ProducerError, "schema_version"):
                        build_kinetum_dpdk.load_policy(root)

    def test_header_staging_rejects_non_string_meson_destination(self):
        """Malformed Meson output cannot silently shrink the header set."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build = root / "build"
            build.mkdir()
            stage = root / "stage"
            meson = root / "meson.py"
            meson.write_text(
                "print('{\"source\":null}')\n",
                encoding="utf-8",
            )
            policy = {
                "builder": {"source_date_epoch": 0},
                "meson_options": {"prefix": "/nonexistent/kinetum-dpdk"},
            }

            with self.assertRaisesRegex(
                build_kinetum_dpdk.ProducerError,
                "non-string destination",
            ):
                build_kinetum_dpdk.copy_declared_headers(
                    policy,
                    meson,
                    build,
                    stage,
                    build_kinetum_dpdk.build_environment(policy, root),
                )

    def test_static_closure_notice_uses_exact_archive_dependency_graph(self):
        """Attribution derives from mapped archive objects and source headers."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "dpdk"
            build = root / "build"
            source_file = source / "lib/example.c"
            header_file = source / "include/example.h"
            object_path = "lib/librte_example.a.p/example.c.o"
            archive_path = "lib/librte_example.a"
            source_file.parent.mkdir(parents=True)
            header_file.parent.mkdir(parents=True)
            (build / object_path).parent.mkdir(parents=True)
            (build / object_path).write_bytes(b"object")
            (build / archive_path).write_bytes(b"archive")
            source_file.write_text(
                "/* SPDX-License-Identifier: BSD-3-Clause\n"
                " * Copyright 2026 Example Source\n"
                " */\n",
                encoding="utf-8",
            )
            header_file.write_text(
                "/* SPDX-License-Identifier: BSD-2-Clause\n"
                " * Copyright 2025 Example Header\n"
                " */\n",
                encoding="utf-8",
            )
            compilation_database = json.dumps(
                [
                    {
                        "directory": str(build),
                        "command": "cc -c example.c",
                        "file": str(source_file),
                        "output": object_path,
                    }
                ]
            ).encode("utf-8")
            dependency_graph = (
                f"{object_path}: #deps 2, deps mtime 1 (VALID)\n"
                f"    {source_file}\n"
                f"    {header_file}\n\n"
            ).encode("utf-8")
            archive_query = (
                f"{archive_path}:\n"
                "  input: STATIC_LINKER\n"
                f"    {object_path}\n"
                "  outputs:\n"
                "    all\n"
            ).encode("utf-8")
            archive_members = b"example.c.o\n"

            def metadata_output(arguments, _environment, _build, _role):
                """Return one exact synthetic build-tool document."""
                command = tuple(arguments)
                if command == ("ninja", "-t", "compdb", "c_COMPILER"):
                    return compilation_database
                if command == ("ninja", "-t", "deps"):
                    return dependency_graph
                if command == ("ninja", "-t", "query", archive_path):
                    return archive_query
                if command == ("ar", "t", str(build / archive_path)):
                    return archive_members
                self.fail(f"unexpected metadata command: {arguments}")

            policy = {
                "dependency": {"version": "24.11.7"},
                "archive_targets": [archive_path],
            }
            with mock.patch.object(
                build_kinetum_dpdk,
                "_build_metadata_output",
                side_effect=metadata_output,
            ):
                notice = build_kinetum_dpdk.render_static_closure_notice(
                    policy,
                    source,
                    build,
                    {},
                )

            self.assertEqual(
                notice,
                "DPDK 24.11.7 static closure copyright notices\n\n"
                "Generated from the exact completed Ninja object and header dependency\n"
                "graph for the declared KinetumDPDK static archives. Paths are relative\n"
                "to the verified DPDK source root. Corresponding license texts are in\n"
                "the adjacent dpdk directory.\n\n"
                "include/example.h\n"
                "  SPDX-License-Identifier: BSD-2-Clause\n"
                "  Copyright 2025 Example Header\n\n"
                "lib/example.c\n"
                "  SPDX-License-Identifier: BSD-3-Clause\n"
                "  Copyright 2026 Example Source\n",
            )

            archive_members = b"foreign.o\n"
            with mock.patch.object(
                build_kinetum_dpdk,
                "_build_metadata_output",
                side_effect=metadata_output,
            ), self.assertRaisesRegex(
                build_kinetum_dpdk.ProducerError,
                "members disagree",
            ):
                build_kinetum_dpdk.render_static_closure_notice(
                    policy,
                    source,
                    build,
                    {},
                )

    def test_generated_configuration_pins_abi_hash_and_optional_absence(self):
        """Generated config identity and optional dependency walls are exact."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "dpdk"
            build = root / "build"
            source.mkdir()
            build.mkdir()
            (source / "ABI_VERSION").write_text("25.0\n", encoding="ascii")
            config = build / "rte_build_config.h"
            exact_text = (
                "#define RTE_HAS_LIBNUMA 1\n"
                "#define RTE_EAL_PMD_PATH "
                '"/nonexistent/kinetum-dpdk/lib/dpdk/pmds-25.0"\n'
            )
            config.write_text(exact_text, encoding="utf-8")
            policy = {
                "generated_config_defines": {"RTE_HAS_LIBNUMA": "1"},
                "forbidden_generated_config_defines": ["RTE_USE_LIBBSD"],
                "meson_options": {
                    "prefix": "/nonexistent/kinetum-dpdk",
                    "libdir": "lib",
                },
                "tuples": {
                    "fixture": {
                        "expected_rte_build_config_sha256": (
                            hashlib.sha256(exact_text.encode("utf-8")).hexdigest()
                        )
                    }
                },
            }

            build_kinetum_dpdk.verify_generated_configuration(
                policy,
                "fixture",
                source,
                build,
            )

            config.write_text(
                exact_text + "#define RTE_USE_LIBBSD 1\n",
                encoding="utf-8",
            )
            policy["tuples"]["fixture"]["expected_rte_build_config_sha256"] = (
                hashlib.sha256((exact_text + "#define RTE_USE_LIBBSD 1\n").encode("utf-8")).hexdigest()
            )
            with self.assertRaisesRegex(
                build_kinetum_dpdk.ProducerError,
                "unexpectedly defines RTE_USE_LIBBSD",
            ):
                build_kinetum_dpdk.verify_generated_configuration(
                    policy,
                    "fixture",
                    source,
                    build,
                )

    def test_static_closure_metadata_rejects_ambiguity_and_stale_rows(self):
        """Every notice input has one complete current representation."""
        # pylint: disable=protected-access
        read_metadata = build_kinetum_dpdk._build_metadata_output
        compdb_parser = build_kinetum_dpdk._parse_compilation_database
        dependency_parser = build_kinetum_dpdk._parse_ninja_dependencies
        member_parser = build_kinetum_dpdk._parse_archive_members
        # pylint: enable=protected-access

        def run_with_output(payload):
            """Invoke the private reader with one synthetic command output."""

            def emit(_arguments, **kwargs):
                """Write tool bytes through the supplied file-backed streams."""
                kwargs["stdout"].write(payload)
                kwargs["stdout"].flush()
                return mock.Mock(returncode=0)

            with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
                build_kinetum_dpdk,
                "BUILD_METADATA_LIMIT_BYTES",
                8,
            ), mock.patch.object(
                build_kinetum_dpdk.subprocess,
                "run",
                side_effect=emit,
            ):
                return read_metadata([], {}, Path(temporary), "fixture metadata")

        self.assertEqual(run_with_output(b"12345678"), b"12345678")
        with self.assertRaisesRegex(
            build_kinetum_dpdk.ProducerError,
            "exceeds its byte bound",
        ):
            run_with_output(b"123456789")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "dpdk"
            build = root / "build"
            source.mkdir()
            build.mkdir()
            source_file = source / "source.c"
            source_file.write_text("int value;\n", encoding="utf-8")
            row = {
                "directory": str(build),
                "command": "cc -c source.c",
                "file": str(source_file),
                "output": "source.c.o",
            }
            malformed_rows = (
                [{**row, "unexpected": True}],
                [row, row],
            )
            for rows in malformed_rows:
                with self.subTest(rows=rows), self.assertRaises(
                    build_kinetum_dpdk.ProducerError
                ):
                    compdb_parser(
                        json.dumps(rows).encode("utf-8"),
                        source,
                        build,
                    )

        stale = b"source.c.o: #deps 1, deps mtime 1 (STALE)\n    source.c\n\n"
        with self.assertRaisesRegex(
            build_kinetum_dpdk.ProducerError,
            "stale evidence",
        ):
            dependency_parser(stale)
        with self.assertRaisesRegex(
            build_kinetum_dpdk.ProducerError,
            "ambiguous member",
        ):
            member_parser(b"source.c.o\nsource.c.o\n", "lib/librte_test.a")

    def test_download_is_bounded_private_and_residue_free(self):
        """Download publication admits exact bytes and cleans every failure."""
        payload = b"12345678"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / "cache"
            cache.mkdir(mode=0o700)
            exact = cache / "exact.tar"
            with mock.patch.object(
                build_kinetum_dpdk.urllib.request,
                "urlopen",
                return_value=io.BytesIO(payload),
            ) as open_url, mock.patch.object(
                build_kinetum_dpdk,
                "DEPENDENCY_DOWNLOAD_LIMIT_BYTES",
                len(payload),
            ), mock.patch.object(
                build_kinetum_dpdk,
                "DEPENDENCY_DOWNLOAD_CHUNK_BYTES",
                3,
            ):
                self.assertEqual(
                    build_kinetum_dpdk.download_verified(
                        "https://example.invalid/exact",
                        digest,
                        exact,
                    ),
                    exact,
                )
            open_url.assert_called_once_with(
                "https://example.invalid/exact",
                timeout=build_kinetum_dpdk.DEPENDENCY_DOWNLOAD_SOCKET_TIMEOUT_SECONDS,
            )
            self.assertEqual(exact.read_bytes(), payload)
            self.assertEqual(exact.stat().st_mode & 0o777, 0o644)

            for name, contents, expected_hash, failure in (
                ("oversized.tar", payload + b"x", digest, "byte bound"),
                ("wrong-hash.tar", payload, "0" * 64, "wrong identity"),
            ):
                with self.subTest(name=name), mock.patch.object(
                    build_kinetum_dpdk.urllib.request,
                    "urlopen",
                    return_value=io.BytesIO(contents),
                ), mock.patch.object(
                    build_kinetum_dpdk,
                    "DEPENDENCY_DOWNLOAD_LIMIT_BYTES",
                    len(payload),
                ), self.assertRaisesRegex(
                    build_kinetum_dpdk.ProducerError,
                    failure,
                ):
                    build_kinetum_dpdk.download_verified(
                        f"https://example.invalid/{name}",
                        expected_hash,
                        cache / name,
                    )
                self.assertFalse((cache / name).exists())

            failed_response = mock.MagicMock()
            failed_response.__enter__.return_value = failed_response
            failed_response.read.side_effect = [b"12", OSError("stream failed")]
            with mock.patch.object(
                build_kinetum_dpdk.urllib.request,
                "urlopen",
                return_value=failed_response,
            ), mock.patch.object(
                build_kinetum_dpdk,
                "DEPENDENCY_DOWNLOAD_LIMIT_BYTES",
                len(payload),
            ), self.assertRaisesRegex(OSError, "stream failed"):
                build_kinetum_dpdk.download_verified(
                    "https://example.invalid/failed",
                    digest,
                    cache / "failed.tar",
                )
            self.assertEqual(
                sorted(path.name for path in cache.iterdir()),
                ["exact.tar"],
            )

    def test_download_cache_races_never_replace_the_winner(self):
        """Exact cache races converge while foreign winners remain untouched."""
        payload = b"exact"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / "cache"
            cache.mkdir(mode=0o700)

            exact_target = cache / "exact.tar"

            def publish_exact_winner(_source: Path, target: Path) -> None:
                """Publish the competing exact object and report lost creation."""
                target.write_bytes(payload)
                target.chmod(0o644)
                raise FileExistsError("race")

            with mock.patch.object(
                build_kinetum_dpdk.urllib.request,
                "urlopen",
                return_value=io.BytesIO(payload),
            ), mock.patch.object(
                build_kinetum_dpdk,
                "_rename_no_replace",
                side_effect=publish_exact_winner,
            ):
                self.assertEqual(
                    build_kinetum_dpdk.download_verified(
                        "https://example.invalid/exact",
                        digest,
                        exact_target,
                    ),
                    exact_target,
                )
            self.assertEqual(exact_target.read_bytes(), payload)

            foreign_target = cache / "foreign.tar"

            def publish_foreign_winner(_source: Path, target: Path) -> None:
                """Publish a competing foreign object without replacing it."""
                target.write_bytes(b"foreign")
                target.chmod(0o644)
                raise FileExistsError("race")

            with mock.patch.object(
                build_kinetum_dpdk.urllib.request,
                "urlopen",
                return_value=io.BytesIO(payload),
            ), mock.patch.object(
                build_kinetum_dpdk,
                "_rename_no_replace",
                side_effect=publish_foreign_winner,
            ), self.assertRaisesRegex(
                build_kinetum_dpdk.ProducerError,
                "foreign object",
            ):
                build_kinetum_dpdk.download_verified(
                    "https://example.invalid/foreign",
                    digest,
                    foreign_target,
                )
            self.assertEqual(foreign_target.read_bytes(), b"foreign")
            self.assertEqual(
                sorted(path.name for path in cache.iterdir()),
                ["exact.tar", "foreign.tar"],
            )

    def test_existing_cache_indirection_and_unsafe_files_are_preserved(self):
        """Existing indirect, writable, or wrong cache objects reject in place."""
        payload = b"exact"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / "cache"
            cache.mkdir(mode=0o700)
            external = Path(temporary) / "external"
            external.write_bytes(payload)
            indirect = cache / "indirect.tar"
            indirect.symlink_to(external)
            writable = cache / "writable.tar"
            writable.write_bytes(payload)
            writable.chmod(0o666)
            wrong = cache / "wrong.tar"
            wrong.write_bytes(b"wrong")
            wrong.chmod(0o644)

            for path in (indirect, writable, wrong):
                with self.subTest(path=path), self.assertRaisesRegex(
                    build_kinetum_dpdk.ProducerError,
                    "wrong identity",
                ):
                    build_kinetum_dpdk.download_verified(
                        "https://example.invalid/unused",
                        digest,
                        path,
                    )
            self.assertTrue(indirect.is_symlink())
            self.assertEqual(external.read_bytes(), payload)
            self.assertEqual(writable.read_bytes(), payload)
            self.assertEqual(wrong.read_bytes(), b"wrong")

    def test_cache_directory_admission_precedes_network_access(self):
        """An indirect or writable cache root rejects before a download."""
        payload = b"exact"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            direct = root / "direct"
            direct.mkdir(mode=0o700)
            indirect = root / "indirect"
            indirect.symlink_to(direct, target_is_directory=True)
            writable = root / "writable"
            writable.mkdir(mode=0o777)
            writable.chmod(0o777)

            for cache, diagnostic in (
                (indirect / "nested", "direct directory"),
                (writable, "untrusted owner or writable mode"),
            ):
                with self.subTest(cache=cache), mock.patch.object(
                    build_kinetum_dpdk.urllib.request,
                    "urlopen",
                ) as open_url, self.assertRaisesRegex(
                    build_kinetum_dpdk.ProducerError,
                    diagnostic,
                ):
                    build_kinetum_dpdk.download_verified(
                        "https://example.invalid/unused",
                        digest,
                        cache / "dependency.tar",
                    )
                open_url.assert_not_called()
            self.assertEqual(list(direct.iterdir()), [])
            self.assertEqual(list(writable.iterdir()), [])

    def test_download_cleanup_double_fault_retains_both_causes(self):
        """A failed download cleanup preserves its originating failure."""
        originating = build_kinetum_dpdk.ProducerError("download failed")
        cleanup = OSError("cleanup failed")
        candidate = mock.MagicMock(spec=Path)
        candidate.unlink.side_effect = cleanup

        with self.assertRaises(
            build_kinetum_dpdk.ProducerDoubleFault
        ) as raised:
            build_kinetum_dpdk._cleanup_file_after_error(  # pylint: disable=protected-access
                candidate,
                originating,
            )

        self.assertIs(raised.exception.originating_error, originating)
        self.assertIs(raised.exception.cleanup_error, cleanup)
        self.assertIs(raised.exception.__cause__, cleanup)

    def test_privileged_host_helpers_are_protected_and_cannot_mask_failure(self):
        """Root-facing helpers use protected Bash and keep known failures nonzero."""
        root = build_kinetum_dpdk.repository_root()
        helpers = {}
        for relative in (
            "tooling/environment/bootstrap_ubuntu.sh",
            "scripts/dpdk_hugepages.sh",
            "scripts/install_trex_ubuntu.sh",
        ):
            script = root / relative
            source = script.read_text(encoding="utf-8")
            helpers[script.name] = source
            with self.subTest(name=script.name), tempfile.TemporaryDirectory() as temporary:
                self.assertTrue(source.startswith("#!/bin/bash -p\n"))
                self.assertIn("[[ $- == *p* ]]", source)
                self.assertIn("export PATH='/usr/sbin:/usr/bin:/sbin:/bin'", source)
                self.assertIn("unset BASH_ENV CDPATH ENV", source)

                unprotected = subprocess.run(
                    ["/bin/bash", str(script), "--help"],
                    check=False, capture_output=True, text=True, timeout=10,
                    env={"PATH": "/usr/bin:/bin"},
                )
                self.assertEqual(unprotected.returncode, 1, unprotected.stderr)
                self.assertEqual(unprotected.stdout, "")
                self.assertIn("helper requires /bin/bash -p", unprotected.stderr)

                startup = Path(temporary) / "startup.sh"
                marker = Path(temporary) / "startup-ran"
                startup.write_text(
                    'printf "unexpected\\n" > "${KINETUM_STARTUP_MARKER}"\n',
                    encoding="utf-8",
                )
                protected = subprocess.run(
                    ["/bin/bash", "-p", str(script), "--help"],
                    check=False, capture_output=True, text=True, timeout=10,
                    env={
                        "PATH": "/usr/bin:/bin",
                        "BASH_ENV": str(startup),
                        "ENV": str(startup),
                        "KINETUM_STARTUP_MARKER": str(marker),
                    },
                )
                self.assertEqual(protected.returncode, 0, protected.stderr)
                self.assertTrue(protected.stdout.startswith("Usage: "))
                self.assertEqual(protected.stderr, "")
                self.assertFalse(marker.exists())

        bootstrap = helpers["bootstrap_ubuntu.sh"]
        self.assertLess(
            bootstrap.rindex("print_required_tool_version tcpdump"),
            bootstrap.rindex("SUCCESS - Ubuntu dependencies installed"),
        )

        hugepages = helpers["dpdk_hugepages.sh"]
        self.assertLess(
            hugepages.index('if ! [[ "$ALLOCATED" =~ ^[0-9]+$ ]]'),
            hugepages.index('if (( 10#$ALLOCATED < 10#$PAGES ))'),
        )
        self.assertLess(
            hugepages.index('if (( 10#$ALLOCATED < 10#$PAGES ))'),
            hugepages.index("SUCCESS - Hugepage setup complete"),
        )

    @staticmethod
    def _write_exact_package(root):
        """Write one minimal package satisfying the complete verifier contract."""
        payload = root / "include/dpdk/rte_config.h"
        payload.parent.mkdir(parents=True)
        payload.write_text("exact\n", encoding="utf-8")
        files = {
            "include/dpdk/rte_config.h": hashlib.sha256(b"exact\n").hexdigest(),
        }
        payload_sha256 = hashlib.sha256(
            f"include/dpdk/rte_config.h:{files['include/dpdk/rte_config.h']}\n".encode("ascii")
        ).hexdigest()
        tuple_row = {"expected_payload_sha256": payload_sha256}
        policy = {
            "dependency": {"version": "24.11.7", "sha256": "b" * 64},
            "build_tool": {"version": "1.12.0", "sha256": "c" * 64},
            "builder": {"os_id": "ubuntu", "source_date_epoch": 0},
            "meson_options": {"buildtype": "release", "b_ndebug": True},
            "reproducibility": {"canonical_build_root": "/usr/src/dpdk"},
            "archive_targets": ["lib/librte_eal.a"],
            "pmd_info_symbols": ["net_i40e_pmd_info"],
            "dynamic_link_libraries": ["numa"],
            "tuples": {"linux-gnu-aarch64": tuple_row},
        }
        manifest = root / build_kinetum_dpdk.PACKAGE_MANIFEST
        manifest.parent.mkdir(parents=True)
        manifest.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "policy_sha256": "a" * 64,
                    "tuple": "linux-gnu-aarch64",
                    "dependency_version": "24.11.7",
                    "dependency_sha256": "b" * 64,
                    "meson_version": "1.12.0",
                    "meson_sha256": "c" * 64,
                    "builder": policy["builder"],
                    "meson_options": policy["meson_options"],
                    "reproducibility": policy["reproducibility"],
                    "tuple_configuration": tuple_row,
                    "payload_sha256": payload_sha256,
                    "archives": ["librte_eal.a"],
                    "pmd_info_symbols": ["net_i40e_pmd_info"],
                    "dynamic_link_libraries": ["numa"],
                    "files": files,
                },
                indent=2,
                sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
        build_kinetum_dpdk.normalize_package_layout(root)
        return payload, manifest, policy

    def test_package_publication_is_preverified_and_atomic(self):
        """A complete package becomes visible only after one candidate check."""
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            stage = parent / "candidate"
            stage.mkdir()
            _payload, _manifest, policy = self._write_exact_package(stage)
            prefix = parent / "published"
            verifier = build_kinetum_dpdk.verify_installed_package

            with mock.patch.object(
                build_kinetum_dpdk,
                "verify_installed_package",
                wraps=verifier,
            ) as verify:
                consumed = build_kinetum_dpdk.publish_package(
                    stage,
                    prefix,
                    policy,
                    "a" * 64,
                    "linux-gnu-aarch64",
                )

            self.assertTrue(consumed)
            self.assertFalse(stage.exists())
            self.assertTrue(
                verifier(
                    prefix,
                    policy,
                    "a" * 64,
                    "linux-gnu-aarch64",
                )
            )
            self.assertEqual(verify.call_count, 1)
            self.assertEqual(verify.call_args.args[0], stage)

    def test_invalid_package_never_reaches_publication(self):
        """A rejected candidate remains private and leaves no public path."""
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            stage = parent / "candidate"
            stage.mkdir(mode=0o755)
            prefix = parent / "published"
            policy = {
                "tuples": {
                    "linux-gnu-aarch64": {
                        "expected_payload_sha256": "0" * 64,
                    }
                }
            }

            with mock.patch.object(
                build_kinetum_dpdk,
                "_rename_no_replace",
            ) as publish, self.assertRaisesRegex(
                build_kinetum_dpdk.ProducerError,
                "failed self-verification",
            ):
                build_kinetum_dpdk.publish_package(
                    stage,
                    prefix,
                    policy,
                    "a" * 64,
                    "linux-gnu-aarch64",
                )

            publish.assert_not_called()
            self.assertTrue(stage.is_dir())
            self.assertFalse(prefix.exists())

    def test_existing_exact_package_preserves_candidate_ownership(self):
        """An exact existing package is idempotent and never replaced."""
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            prefix = parent / "published"
            prefix.mkdir()
            target_payload, _target_manifest, policy = self._write_exact_package(
                prefix
            )
            stage = parent / "candidate"
            stage.mkdir()
            candidate_payload, _candidate_manifest, _ = self._write_exact_package(
                stage
            )

            consumed = build_kinetum_dpdk.publish_package(
                stage,
                prefix,
                policy,
                "a" * 64,
                "linux-gnu-aarch64",
            )

            self.assertFalse(consumed)
            self.assertTrue(stage.is_dir())
            self.assertEqual(candidate_payload.read_bytes(), b"exact\n")
            self.assertEqual(target_payload.read_bytes(), b"exact\n")

    def test_package_races_preserve_exact_or_foreign_winner(self):
        """A package race converges only on an independently exact winner."""
        for winner_is_exact in (True, False):
            with (
                self.subTest(winner_is_exact=winner_is_exact),
                tempfile.TemporaryDirectory() as temporary,
            ):
                parent = Path(temporary).resolve()
                stage = parent / "candidate"
                stage.mkdir()
                _payload, _manifest, policy = self._write_exact_package(stage)
                prefix = parent / "published"

                def publish_winner(
                    _source: Path,
                    target: Path,
                    exact: bool = winner_is_exact,
                ) -> None:
                    """Publish one competing winner and report the lost race."""
                    target.mkdir()
                    if exact:
                        self._write_exact_package(target)
                    else:
                        foreign = target / "foreign"
                        foreign.write_bytes(b"foreign")
                        foreign.chmod(0o644)
                        target.chmod(0o755)
                    raise FileExistsError("race")

                with mock.patch.object(
                    build_kinetum_dpdk,
                    "_rename_no_replace",
                    side_effect=publish_winner,
                ):
                    if winner_is_exact:
                        self.assertFalse(
                            build_kinetum_dpdk.publish_package(
                                stage,
                                prefix,
                                policy,
                                "a" * 64,
                                "linux-gnu-aarch64",
                            )
                        )
                    else:
                        with self.assertRaisesRegex(
                            build_kinetum_dpdk.ProducerError,
                            "foreign object",
                        ):
                            build_kinetum_dpdk.publish_package(
                                stage,
                                prefix,
                                policy,
                                "a" * 64,
                                "linux-gnu-aarch64",
                            )
                self.assertTrue(stage.is_dir())
                if winner_is_exact:
                    self.assertTrue(
                        build_kinetum_dpdk.verify_installed_package(
                            prefix,
                            policy,
                            "a" * 64,
                            "linux-gnu-aarch64",
                        )
                    )
                else:
                    self.assertEqual((prefix / "foreign").read_bytes(), b"foreign")

    def test_package_cleanup_double_fault_retains_both_causes(self):
        """A failed package cleanup preserves both independent failures."""
        originating = build_kinetum_dpdk.ProducerError("build failed")
        cleanup = OSError("cleanup failed")
        candidate = Path("/unreached/package-candidate")

        with mock.patch.object(
            build_kinetum_dpdk.shutil,
            "rmtree",
            side_effect=cleanup,
        ), self.assertRaises(
            build_kinetum_dpdk.ProducerDoubleFault
        ) as raised:
            build_kinetum_dpdk._cleanup_directory_after_error(  # pylint: disable=protected-access
                candidate,
                originating,
            )

        self.assertIs(raised.exception.originating_error, originating)
        self.assertIs(raised.exception.cleanup_error, cleanup)
        self.assertIs(raised.exception.__cause__, cleanup)

    def test_build_environment_is_closed_and_path_independent(self):
        """Native tools receive only the complete source-controlled environment."""
        policy = {"builder": {"source_date_epoch": 17}}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            environment = build_kinetum_dpdk.build_environment(policy, root)

            self.assertEqual(
                environment,
                {
                    "HOME": str(root / "home"),
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PATH": "/usr/bin:/bin",
                    "PKG_CONFIG_LIBDIR": str(root / "pkgconfig"),
                    "PKG_CONFIG_PATH": "",
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONHASHSEED": "0",
                    "PYTHONNOUSERSITE": "1",
                    "SOURCE_DATE_EPOCH": "17",
                    "TMPDIR": str(root / "tmp"),
                    "TZ": "UTC",
                    "ZERO_AR_DATE": "1",
                },
            )
            self.assertTrue((root / "home").is_dir())
            self.assertTrue((root / "tmp").is_dir())
            self.assertTrue((root / "pkgconfig").is_dir())

    def test_package_umask_cannot_publish_a_root_only_layout(self):
        """Producer policy cannot remove access required by build consumers."""
        with self.assertRaisesRegex(
            build_kinetum_dpdk.ProducerError,
            "does not produce the exact reader-safe package modes",
        ):
            build_kinetum_dpdk.apply_package_umask(
                {"reproducibility": {"package_umask": "0077"}}
            )

    def test_package_owner_allows_root_or_the_exact_consumer(self):
        """Ordinary CMake can verify root-produced immutable dependencies."""
        # pylint: disable=protected-access
        owner_is_trusted = build_kinetum_dpdk._package_owner_is_trusted
        # pylint: enable=protected-access
        with mock.patch.object(build_kinetum_dpdk.os, "geteuid", return_value=1000):
            self.assertTrue(owner_is_trusted(0))
            self.assertTrue(owner_is_trusted(1000))
            self.assertFalse(owner_is_trusted(1001))

    def test_meson_c_arguments_preserve_exact_argument_boundaries(self):
        """Meson must receive each reproducibility flag as one C argument."""
        root = build_kinetum_dpdk.repository_root()
        policy, _ = build_kinetum_dpdk.load_policy(root)
        tuple_row = policy["tuples"]["linux-gnu-aarch64"]
        source = Path("/tmp/producer-source")
        resolved_source_root = source.parent.resolve()
        arguments = build_kinetum_dpdk.meson_arguments(
            policy,
            tuple_row,
            Path("/tmp/meson.py"),
            source,
            Path("/tmp/producer-build"),
            Path("/tmp/producer-native.ini"),
        )
        self.assertEqual(
            arguments[arguments.index("--native-file") + 1],
            "/tmp/producer-native.ini",
        )
        encoded = next(
            argument.removeprefix("-Dc_args=")
            for argument in arguments
            if argument.startswith("-Dc_args=")
        )

        self.assertEqual(
            shlex.split(encoded),
            [
                "-fvisibility=hidden",
                f"-ffile-prefix-map={resolved_source_root}="
                "/usr/src/kinetum-dpdk-24.11.7",
                f"-fmacro-prefix-map={resolved_source_root}="
                "/usr/src/kinetum-dpdk-24.11.7",
                f"-fdebug-prefix-map={resolved_source_root}="
                "/usr/src/kinetum-dpdk-24.11.7",
            ],
        )

    def test_verified_extraction_accepts_in_root_relative_symlink(self):
        """An upstream relative link may traverse only within the exact root."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "dependency.tar"
            payload = b"exact upstream tool\n"
            archive_root = "dpdk-stable-24.11.7"
            target_name = (
                f"{archive_root}/drivers/dma/idxd/dpdk_idxd_cfg.py"
            )
            link_name = (
                f"{archive_root}/drivers/raw/ioat/dpdk_idxd_cfg.py"
            )
            with tarfile.open(archive, "w") as output:
                target = tarfile.TarInfo(target_name)
                target.size = len(payload)
                output.addfile(target, io.BytesIO(payload))
                link = tarfile.TarInfo(link_name)
                link.type = tarfile.SYMTYPE
                link.linkname = "../../dma/idxd/dpdk_idxd_cfg.py"
                output.addfile(link)

            destination = root / "extracted"
            destination.mkdir()
            extracted = build_kinetum_dpdk.extract_verified(
                archive, destination, archive_root
            )

            extracted_link = extracted / "drivers/raw/ioat/dpdk_idxd_cfg.py"
            self.assertTrue(extracted_link.is_symlink())
            self.assertEqual(extracted_link.read_bytes(), payload)

    def test_verified_extraction_rejects_link_outside_exact_root(self):
        """A symbolic or hard link outside the exact root must reject."""
        cases = (
            ("relative symlink", tarfile.SYMTYPE, "../../../../outside.py"),
            ("absolute symlink", tarfile.SYMTYPE, "/etc/passwd"),
            ("outside hard link", tarfile.LNKTYPE, "outside.py"),
        )
        for name, link_type, link_target in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "dependency.tar"
                archive_root = "dpdk-stable-24.11.7"
                link_name = (
                    f"{archive_root}/drivers/raw/ioat/escaping_link.py"
                )
                with tarfile.open(archive, "w") as output:
                    link = tarfile.TarInfo(link_name)
                    link.type = link_type
                    link.linkname = link_target
                    output.addfile(link)

                destination = root / "extracted"
                destination.mkdir()
                with self.assertRaisesRegex(
                    build_kinetum_dpdk.ProducerError,
                    "dependency archive contains an escaping link",
                ):
                    build_kinetum_dpdk.extract_verified(
                        archive, destination, archive_root
                    )
                self.assertEqual(list(destination.iterdir()), [])

    def test_installed_package_rejects_tampered_content(self):
        """The verifier binds file bytes and exact JSON types throughout metadata."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload, manifest, policy = self._write_exact_package(root)
            self.assertTrue(
                build_kinetum_dpdk.verify_installed_package(
                    root,
                    policy,
                    "a" * 64,
                    "linux-gnu-aarch64",
                )
            )

            original = manifest.read_text(encoding="utf-8")
            for key, value in (
                ("schema_version", True),
                ("schema_version", 1.0),
                ("builder", {"os_id": "ubuntu", "source_date_epoch": False}),
                ("meson_options", {"buildtype": "release", "b_ndebug": 1}),
            ):
                with self.subTest(metadata_field=key, value=value):
                    document = json.loads(original)
                    document[key] = value
                    manifest.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                    self.assertFalse(build_kinetum_dpdk.verify_installed_package(
                        root, policy, "a" * 64, "linux-gnu-aarch64"
                    ))
            manifest.write_text(original, encoding="utf-8")

            payload.write_text("tampered\n", encoding="utf-8")

            self.assertFalse(
                build_kinetum_dpdk.verify_installed_package(
                    root,
                    policy,
                    "a" * 64,
                    "linux-gnu-aarch64",
                )
            )

            tampered_files = {
                "include/dpdk/rte_config.h": hashlib.sha256(b"tampered\n").hexdigest(),
            }
            tampered_payload_sha256 = hashlib.sha256(
                f"include/dpdk/rte_config.h:{tampered_files['include/dpdk/rte_config.h']}\n".encode("ascii")
            ).hexdigest()
            document = json.loads(manifest.read_text(encoding="utf-8"))
            document["payload_sha256"] = tampered_payload_sha256
            document["files"] = tampered_files
            manifest.write_text(
                json.dumps(document, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            self.assertFalse(
                build_kinetum_dpdk.verify_installed_package(
                    root,
                    policy,
                    "a" * 64,
                    "linux-gnu-aarch64",
                )
            )

    def test_complete_candidate_normalizes_to_reader_safe_package_modes(self):
        """A private staging root becomes exact only after complete assembly."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = root / "candidate"
            stage.mkdir(mode=0o700)
            directory = stage / "include/dpdk"
            directory.mkdir(parents=True, mode=0o700)
            payload = directory / "rte_config.h"
            payload.write_text("exact\n", encoding="utf-8")
            payload.chmod(0o600)

            build_kinetum_dpdk.normalize_package_layout(stage)

            self.assertEqual(
                stage.stat().st_mode & 0o777,
                build_kinetum_dpdk.PACKAGE_DIRECTORY_MODE,
            )
            self.assertEqual(
                directory.stat().st_mode & 0o777,
                build_kinetum_dpdk.PACKAGE_DIRECTORY_MODE,
            )
            self.assertEqual(
                payload.stat().st_mode & 0o777,
                build_kinetum_dpdk.PACKAGE_FILE_MODE,
            )
            alias = stage / "rte_config.link"
            alias.symlink_to(payload)
            with self.assertRaisesRegex(
                build_kinetum_dpdk.ProducerError,
                "contains a non-regular entry",
            ):
                build_kinetum_dpdk.normalize_package_layout(stage)

    def test_installed_package_rejects_any_permission_drift(self):
        """Verification binds exact directory and regular-file modes."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload, manifest, policy = self._write_exact_package(root)
            cases = (
                (root, 0o700, build_kinetum_dpdk.PACKAGE_DIRECTORY_MODE),
                (
                    payload.parent,
                    0o700,
                    build_kinetum_dpdk.PACKAGE_DIRECTORY_MODE,
                ),
                (payload, 0o600, build_kinetum_dpdk.PACKAGE_FILE_MODE),
                (manifest, 0o600, build_kinetum_dpdk.PACKAGE_FILE_MODE),
            )

            for path, invalid_mode, exact_mode in cases:
                with self.subTest(path=path.relative_to(root)):
                    path.chmod(invalid_mode)
                    self.assertFalse(
                        build_kinetum_dpdk.verify_installed_package(
                            root,
                            policy,
                            "a" * 64,
                            "linux-gnu-aarch64",
                        )
                    )
                    path.chmod(exact_mode)
                    self.assertTrue(
                        build_kinetum_dpdk.verify_installed_package(
                            root,
                            policy,
                            "a" * 64,
                            "linux-gnu-aarch64",
                        )
                    )

    def test_default_package_root_is_content_addressed(self):
        """A policy change selects a new immutable package root."""
        first = build_kinetum_dpdk.default_package_prefix(
            "24.11.7", "linux-gnu-aarch64", "a" * 64
        )
        second = build_kinetum_dpdk.default_package_prefix(
            "24.11.7", "linux-gnu-aarch64", "b" * 64
        )

        self.assertEqual(
            first,
            Path("/opt/kinetum/dependencies/dpdk/24.11.7/")
            / "linux-gnu-aarch64"
            / ("a" * 64),
        )
        self.assertNotEqual(first, second)

    def test_header_staging_maps_exact_meson_public_tree(self):
        """Public header bytes move under the package's private include root."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build = root / "build"
            build.mkdir()
            stage = root / "stage"
            source = root / "source/rte_config.h"
            source.parent.mkdir()
            source.write_text("exact\n", encoding="utf-8")
            meson = root / "meson.py"
            destination = (
                "/nonexistent/kinetum-dpdk-dynamic-pmds-disabled/"
                "include/rte_config.h"
            )
            meson.write_text(
                "import json\n"
                f"print(json.dumps({{{str(source)!r}: {destination!r}}}))\n",
                encoding="utf-8",
            )
            policy = {
                "builder": {"source_date_epoch": 0},
                "meson_options": {
                    "prefix": "/nonexistent/kinetum-dpdk-dynamic-pmds-disabled"
                }
            }

            build_kinetum_dpdk.copy_declared_headers(
                policy,
                meson,
                build,
                stage,
                build_kinetum_dpdk.build_environment(policy, root),
            )

            self.assertEqual(
                (stage / "include/dpdk/rte_config.h").read_text(
                    encoding="utf-8"
                ),
                "exact\n",
            )

    def test_header_staging_rejects_source_outside_verified_build(self):
        """Meson cannot redirect a public header to an unverified source."""
        with (
            tempfile.TemporaryDirectory() as temporary,
            tempfile.TemporaryDirectory() as external,
        ):
            root = Path(temporary)
            build = root / "build"
            build.mkdir()
            stage = root / "stage"
            source = Path(external) / "rte_config.h"
            source.write_text("foreign\n", encoding="utf-8")
            meson = root / "meson.py"
            destination = (
                "/nonexistent/kinetum-dpdk-dynamic-pmds-disabled/"
                "include/rte_config.h"
            )
            meson.write_text(
                "import json\n"
                f"print(json.dumps({{{str(source)!r}: {destination!r}}}))\n",
                encoding="utf-8",
            )
            policy = {
                "builder": {"source_date_epoch": 0},
                "meson_options": {
                    "prefix": "/nonexistent/kinetum-dpdk-dynamic-pmds-disabled"
                },
            }

            with self.assertRaisesRegex(
                build_kinetum_dpdk.ProducerError,
                "escapes the verified build",
            ):
                build_kinetum_dpdk.copy_declared_headers(
                    policy,
                    meson,
                    build,
                    stage,
                    build_kinetum_dpdk.build_environment(policy, root),
                )
