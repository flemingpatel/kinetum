#!/usr/bin/env python3
"""Test documentation ownership, publication, and process bounds."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import venv
from unittest import mock

from tooling.release.documentation import build_documentation as docs
from tooling.release.documentation import documentation_process as process_owner
from tooling.release.documentation import documentation_publication as publication_owner


def _create_minimal_documentation_product(
    root: pathlib.Path,
) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    """Create a complete documentation source-and-product fixture."""

    source = root / "source"
    output = root / "output"
    product = output / "html"
    (source / "docs" / "diagrams").mkdir(parents=True)
    (source / "src" / "modules").mkdir(parents=True)
    (source / "include" / "kinetum").mkdir(parents=True)
    (source / "tooling/release/documentation").mkdir(parents=True)
    (source / "tooling/environment").mkdir(parents=True)
    (source / "tooling/environment/requirements.lock").write_text("sphinx==8.1.3\n", encoding="ascii")
    (source / "VERSION").write_text("0.1.0\n", encoding="ascii")
    (source / "include" / "kinetum" / "api.h").write_text("void api(void);\n", encoding="ascii")
    for name in ("build_documentation.py", "documentation_process.py", "documentation_publication.py"):
        (source / "tooling/release/documentation" / name).write_text(
            '"""Fixture producer input."""\n', encoding="ascii"
        )
    license_root = source / "third_party" / "documentation" / "licenses"
    license_root.mkdir(parents=True)
    output.mkdir()
    product.mkdir()
    (product / "api").mkdir()
    (product / "diagrams").mkdir()
    (product / "_licenses").mkdir()

    (source / "docs" / "README.md").write_text("# Docs\n", encoding="utf-8")
    (source / "docs" / "diagrams" / "ordered_cut_boundary_protocol.md").write_text(
        "# Ordered CUT\n", encoding="utf-8"
    )
    (source / "CHANGELOG.md").write_text("# Release\n", encoding="utf-8")
    (source / "src" / "modules" / "README.md").write_text(
        "# Modules\n", encoding="utf-8"
    )
    (source / "LICENSE").write_text("license\n", encoding="utf-8")
    (license_root / "README.md").write_text("asset licenses\n", encoding="utf-8")
    (license_root / "FONT_NOTICES.md").write_text(
        "font notices\n", encoding="utf-8"
    )

    product_files = {
        "index.html": "<html><body>index</body></html>\n",
        "README.html": "<html><body>docs</body></html>\n",
        "RELEASE_NOTES.html": "<html><body>release</body></html>\n",
        "BUILTIN_MODULES.html": "<html><body>modules</body></html>\n",
        "diagrams/ordered_cut_boundary_protocol.html": (
            "<html><body>ordered CUT</body></html>\n"
        ),
        "searchindex.js": "const searchIndex = {};\n",
        "api/index.html": "<html><body>Doxygen API</body></html>\n",
        "_licenses/README.md": "asset licenses\n",
        "_licenses/FONT_NOTICES.md": "font notices\n",
        "_licenses/APACHE-2.0.txt": "license\n",
    }
    for relative, contents in product_files.items():
        (product / relative).write_text(contents, encoding="utf-8")
    identities = []
    for input_root in (source, product):
        digest = hashlib.sha256()
        for path in sorted(input_root.rglob("*")):
            if path.is_file():
                digest.update(path.relative_to(input_root).as_posix().encode("utf-8") + b"\0")
                digest.update(hashlib.sha256(path.read_bytes()).digest())
        identities.append(digest.hexdigest())
    (product / "build_manifest.json").write_text(
        json.dumps({"source_sha256": identities[0], "payload_sha256": identities[1]}) + "\n",
        encoding="ascii",
    )
    return source, output, product


class DocumentationBuildTest(unittest.TestCase):
    """Exercise page ownership, renderer admission, and site publication."""

    def test_public_page_graph_preserves_authored_order(self) -> None:
        """The root's link order determines one complete hidden toctree order."""

        edges = {
            "docs/README.md": ["docs/A.md", "src/modules/README.md"],
            "docs/A.md": ["docs/diagrams/B.md", "CHANGELOG.md"],
            "docs/diagrams/B.md": [],
            "src/modules/README.md": [],
            "CHANGELOG.md": [],
        }
        self.assertEqual(
            docs._ordered_reachable_pages(edges),  # pylint: disable=protected-access
            [
                "docs/README.md",
                "docs/A.md",
                "src/modules/README.md",
                "docs/diagrams/B.md",
                "CHANGELOG.md",
            ],
        )

    def test_public_page_graph_rejects_orphan(self) -> None:
        """A public page outside the root graph cannot silently miss Sphinx."""

        edges = {"docs/README.md": [], "docs/orphan.md": []}
        with self.assertRaisesRegex(docs.DocumentationError, "not reachable"):
            docs._ordered_reachable_pages(edges)  # pylint: disable=protected-access

    def test_generated_link_rewrite_keeps_anchor(self) -> None:
        """External canonical pages map into staging without losing anchors."""

        pages = {
            "docs/README.md": "README.md",
            "docs/diagrams/map.md": "diagrams/map.md",
            "src/modules/README.md": "BUILTIN_MODULES.md",
        }
        source = "See [modules](../../src/modules/README.md#acl)."
        self.assertEqual(
            docs._rewrite_links(  # pylint: disable=protected-access
                source, "docs/diagrams/map.md", pages
            ),
            "See [modules](../BUILTIN_MODULES.md#acl).",
        )

    def test_rendered_plantuml_membership_requires_actual_svg_images(self) -> None:
        """Missing, duplicated, or non-image diagrams cannot satisfy authored membership."""

        with tempfile.TemporaryDirectory() as directory:
            source, output, product = _create_minimal_documentation_product(pathlib.Path(directory).resolve())
            (source / "docs" / "README.md").write_text(
                "# Docs\n\n```{uml}\n@startuml\nA -> B: packet\n@enduml\n```\n", encoding="ascii"
            )
            image_name = "plantuml-" + "a" * 40 + ".svg"
            (product / "_images").mkdir()
            (product / "_images" / image_name).write_text(
                '<svg xmlns="http://www.w3.org/2000/svg"><text>packet</text></svg>\n', encoding="ascii"
            )
            image = f'<p class="plantuml"><img src="_images/{image_name}" alt="packet"/></p>\n'
            page = product / "README.html"
            page.write_text(image, encoding="ascii")
            docs._verify_site_tree(source, output, product)  # pylint: disable=protected-access
            for invalid in ("<p>packet</p>", '<p class="plantuml">packet</p>', image + image):
                page.write_text(invalid, encoding="ascii")
                with self.subTest(value=invalid), self.assertRaisesRegex(
                    docs.DocumentationError, "rendered PlantUML membership"
                ):
                    docs._verify_site_tree(source, output, product)  # pylint: disable=protected-access
            page.write_text(image, encoding="ascii")
            (product / "_images" / image_name).unlink()
            with self.assertRaisesRegex(docs.DocumentationError, "missing site member"):
                docs._verify_site_tree(source, output, product)  # pylint: disable=protected-access

    def test_version_reader_requires_one_canonical_line(self) -> None:
        """Sphinx metadata can come only from the repository VERSION shape."""

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "VERSION").write_text("0.1.0\n", encoding="utf-8")
            self.assertEqual(docs._read_version(root), "0.1.0")  # pylint: disable=protected-access
            for invalid in (b"0.1.0", b"0.1.0\r\n", b"0.1.0\n\0", b" 0.1.0\n", b"0.1.0\n\n"):
                (root / "VERSION").write_bytes(invalid)
                with self.subTest(value=invalid), self.assertRaisesRegex(docs.DocumentationError, "canonical"):
                    docs._read_version(root)  # pylint: disable=protected-access

    def test_generated_child_rejects_path_components(self) -> None:
        """A generated-directory selector cannot escape its exact output root."""

        with self.assertRaisesRegex(
            publication_owner.DocumentationPublicationError, "path atom"
        ):
            publication_owner.generated_path(
                pathlib.Path("/tmp/build-docs"), "../source"
            )
        with self.assertRaisesRegex(
            publication_owner.DocumentationPublicationError, "absolute"
        ):
            publication_owner.generated_path(pathlib.Path("build-docs"), "html")

    def test_python_build_backend_retains_the_shared_lock_hashes(self) -> None:
        """Backend bootstrapping selects only its complete source-controlled requirement."""

        with tempfile.TemporaryDirectory() as directory:
            lock = pathlib.Path(directory) / "requirements.lock"
            backend = (
                "setuptools==84.0.0 \\\n    --hash=sha256:" + "a" * 64
                + " \\\n    --hash=sha256:" + "b" * 64 + "\n"
            )
            lock.write_text("sphinx==8.1.3\n" + backend + "wheel==0.48.0\n", encoding="ascii")
            self.assertEqual(
                docs._python_build_requirements(lock), backend  # pylint: disable=protected-access
            )
            for invalid in ("sphinx==8.1.3\n", "setuptools==84.0.0\n"):
                lock.write_text(invalid, encoding="ascii")
                with self.subTest(value=invalid), self.assertRaisesRegex(
                    docs.DocumentationError, "hash-pinned setuptools"
                ):
                    docs._python_build_requirements(lock)  # pylint: disable=protected-access

    def test_backend_installer_owns_its_input_and_preserves_consumer_failure(self) -> None:
        """The owner shell replaces unreadable inherited stdin and propagates consumer status."""

        root = pathlib.Path(__file__).resolve().parents[2]
        source = (root / "tooling/environment/bootstrap_ubuntu.sh").read_text(encoding="ascii")
        begin = source.index("/bin/bash -p -c ")
        end = source.index(" kinetum-python-backend", begin)
        command = shlex.split(source[begin:end])
        backend = docs._python_build_requirements(  # pylint: disable=protected-access
            root / "tooling/environment/requirements.lock"
        )
        with tempfile.TemporaryDirectory() as directory:
            reader = pathlib.Path(directory) / "requirements reader.sh"
            reader.write_text(
                '#!/bin/sh\nset -eu\n'
                'while [ "$#" -gt 0 ]; do\n'
                '  if [ "$1" = "-r" ]; then\n'
                '    /bin/cat "$2"\n'
                '    exit "$KINETUM_BACKEND_TEST_EXIT"\n'
                '  fi\n'
                '  shift\n'
                'done\nexit 64\n',
                encoding="ascii",
            )
            reader.chmod(0o700)
            for status in (0, 23):
                with self.subTest(status=status), tempfile.TemporaryFile() as inherited:
                    inherited.write(b"inherited input must not supply requirements\n")
                    inherited.seek(0)
                    os.fchmod(inherited.fileno(), 0)
                    result = subprocess.run(
                        [*command, "kinetum-python-backend", backend.rstrip("\n"), str(reader)],
                        stdin=inherited, capture_output=True, check=False, timeout=10,
                        env={"PATH": "/usr/bin:/bin", "KINETUM_BACKEND_TEST_EXIT": str(status)},
                    )
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertEqual(result.stdout.decode("ascii"), backend)
                    self.assertEqual(result.stderr, b"")

    def test_documentation_json_admission_is_bounded_and_unambiguous(self) -> None:
        """Toolchain JSON rejects duplicate, non-finite, and invalid text."""
        parser = docs._parse_json_object  # pylint: disable=protected-access
        self.assertEqual(
            parser('{"nested":{"items":[1,"ok",true]}}', "fixture"),
            {"nested": {"items": [1, "ok", True]}},
        )
        malformed = (
            '{"key":1,"key":2}',
            '{"nested":{"key":1,"key":2}}',
            '{"value":NaN}',
            '{"value":Infinity}',
            '{"value":-Infinity}',
            '{"value":1e999}',
            '{"\\ud800":"value"}',
            '{"value":"\\udfff"}',
        )
        for raw in malformed:
            with self.subTest(raw=raw), self.assertRaises(docs.DocumentationError):
                parser(raw, "fixture")
        with self.assertRaises(docs.DocumentationError):
            parser("[]", "fixture")

        prefix = b'{"value":"'
        suffix = b'"}'
        exact = prefix + b"x" * (
            docs.DOCUMENTATION_JSON_LIMIT_BYTES - len(prefix) - len(suffix)
        ) + suffix
        self.assertEqual(len(exact), docs.DOCUMENTATION_JSON_LIMIT_BYTES)
        exact_text = exact.decode("ascii")
        self.assertEqual(
            len(parser(exact_text, "fixture")["value"]),
            len(exact) - 12,
        )
        with self.assertRaises(docs.DocumentationError):
            parser(exact_text + " ", "fixture")

    def test_python_probe_rejects_unknown_json_member(self) -> None:
        """The exact metadata probe cannot add an unconsumed authority."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            python = root / "python3"
            python.write_text("", encoding="utf-8")
            python.chmod(0o755)
            with mock.patch.object(
                docs,
                "_run_small",
                return_value=(
                    '{"python":[3,12,3],"prefix":"/venv","base_prefix":"/usr",'
                    '"packages":[],"extra":true}'
                ),
            ), self.assertRaisesRegex(docs.DocumentationError, "unknown fields"):
                docs._validate_python_toolchain(  # pylint: disable=protected-access
                    root,
                    python,
                )

    def test_build_environment_removes_python_and_loader_injection(self) -> None:
        """Documentation subprocesses remove injection while preserving ordinary state."""

        with mock.patch.dict(
            os.environ,
            {
                "DYLD_INSERT_LIBRARIES": "/untrusted.dylib",
                "KEEP": "yes",
                "LD_PRELOAD": "/untrusted.so",
                "JAVA_TOOL_OPTIONS": "-javaagent:/untrusted.jar",
                "_JAVA_OPTIONS": "-javaagent:/untrusted.jar",
                "JDK_JAVA_OPTIONS": "-javaagent:/untrusted.jar",
                "CLASSPATH": "/untrusted.jar",
                "GRAPHVIZ_DOT": "/untrusted-dot",
                "GVBINDIR": "/untrusted-graphviz-plugins",
                "GV_FILE_PATH": "/untrusted-graphviz-files",
                "PLANTUML_SECURITY_PROFILE": "UNSECURE",
                "PIP_TARGET": "/untrusted-target",
                "PIP_CONFIG_FILE": "/untrusted-pip.conf",
                "PYTHONPATH": "/untrusted",
            },
            clear=True,
        ):
            environment = docs._build_environment()  # pylint: disable=protected-access
        for name in ("PYTHONPATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "JAVA_TOOL_OPTIONS",
                     "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH", "GRAPHVIZ_DOT",
                     "GVBINDIR", "GV_FILE_PATH", "PLANTUML_SECURITY_PROFILE", "PIP_TARGET"):
            self.assertNotIn(name, environment)
        self.assertEqual(environment["PIP_CONFIG_FILE"], os.devnull)
        self.assertEqual(environment["KEEP"], "yes")
        self.assertEqual(environment["SOURCE_DATE_EPOCH"], "0")

    def test_metadata_probe_receives_the_sanitized_environment(self) -> None:
        """A metadata probe cannot recover ambient interpreter or loader hooks."""

        completed = mock.Mock(returncode=0, output=b"exact\n")
        with mock.patch.dict(
            os.environ,
            {"LD_PRELOAD": "/untrusted.so", "JAVA_TOOL_OPTIONS": "-javaagent:/untrusted.jar"},
            clear=True,
        ), mock.patch.object(
            docs.DOCUMENTATION_PROCESS, "run_captured", return_value=completed
        ) as run:
            self.assertEqual(
                docs._run_small(  # pylint: disable=protected-access
                    ["/exact/tool", "--version"],
                    "tool probe",
                    pathlib.Path.cwd().resolve(),
                ),
                "exact",
            )

        child_environment = run.call_args.kwargs["environment"]
        self.assertNotIn("LD_PRELOAD", child_environment)
        self.assertNotIn("JAVA_TOOL_OPTIONS", child_environment)
        self.assertEqual(child_environment["SOURCE_DATE_EPOCH"], "0")
        self.assertEqual(
            run.call_args.kwargs["working_directory"], pathlib.Path.cwd().resolve()
        )

    def test_tool_preparation_installs_the_locked_backend_before_source_packages(self) -> None:
        """Source package installation follows the locked backend setup."""

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            source = root / "source"
            destination = root / "tools"
            (source / "tooling/environment").mkdir(parents=True)
            destination.mkdir()
            lock = source / "tooling/environment/requirements.lock"
            backend = "setuptools==84.0.0 \\\n    --hash=sha256:" + "a" * 64 + "\n"
            lock.write_text(backend + "sphinxcontrib-plantuml==0.31\n", encoding="ascii")
            commands = []
            observed_backend = []

            def run(command: list[str], _role: str, environment: dict[str, str], _root: pathlib.Path) -> None:
                """Retain command order and backend bytes before private cleanup."""

                commands.append(command)
                self.assertEqual(environment["PIP_CONFIG_FILE"], os.devnull)
                self.assertEqual(environment["HOME"], str(destination / "home"))
                if "--no-deps" in command:
                    observed_backend.append(pathlib.Path(command[-1]).read_text(encoding="ascii"))

            with mock.patch.object(docs, "_install_plantuml") as install_jar, mock.patch.object(
                docs, "_run_build", side_effect=run
            ), mock.patch.object(docs.sys, "executable", "/usr/bin/python3"):
                docs._populate_tools(source, destination)  # pylint: disable=protected-access
            self.assertEqual(commands[0], [
                "/usr/bin/python3", "-I", "-B", "-m", "venv", str(destination / "venv")
            ])
            python = str(destination / "venv/bin/python3.12")
            self.assertEqual(observed_backend, [backend])
            self.assertEqual(len(commands), 3)
            for command in commands[1:]:
                self.assertEqual(command[0], python)
                self.assertIn("--require-hashes", command)
            self.assertIn("--no-build-isolation", commands[2])
            self.assertIn("--no-binary=sphinxcontrib-plantuml", commands[2])
            self.assertEqual(commands[2][-1], str(lock))
            self.assertFalse((destination / "build-requirements.lock").exists())
            install_jar.assert_called_once_with(destination)

    def test_plantuml_download_admits_hash_and_size_before_use(self) -> None:
        """The downloaded renderer must satisfy its byte limit and exact digest."""

        payload = b"fixture renderer"
        digest = hashlib.sha256(payload).hexdigest()
        cases = (
            (digest, len(payload), None),
            ("0" * 64, len(payload), "SHA-256 pin"),
            (digest, len(payload) - 1, "byte bound"),
        )
        for expected, limit, diagnostic in cases:
            with self.subTest(diagnostic=diagnostic), tempfile.TemporaryDirectory() as directory:
                destination = pathlib.Path(directory).resolve()
                jar = destination / "plantuml.jar"
                jar.write_bytes(payload)
                with mock.patch.object(docs, "_discover_tool", return_value=pathlib.Path("/usr/bin/curl")), \
                        mock.patch.object(docs, "_run_build") as download, \
                        mock.patch.object(docs, "PLANTUML_SHA256", expected), \
                        mock.patch.object(docs, "PLANTUML_JAR_LIMIT_BYTES", limit):
                    if diagnostic:
                        with self.assertRaisesRegex(docs.DocumentationError, diagnostic):
                            docs._install_plantuml(destination)  # pylint: disable=protected-access
                    else:
                        self.assertEqual(
                            docs._install_plantuml(destination), jar  # pylint: disable=protected-access
                        )
                command = download.call_args.args[0]
                self.assertEqual(command[:3], ["/usr/bin/curl", "--disable", "--fail"])
                self.assertEqual(command[command.index("--max-filesize") + 1], str(limit))
                self.assertEqual(
                    command[-1],
                    "https://github.com/plantuml/plantuml/releases/download/v1.2026.8/plantuml-1.2026.8.jar"
                )
                self.assertEqual(command[command.index("--output") + 1], str(jar))

    def test_tool_alias_is_retained_only_when_invocation_path_is_semantic(self) -> None:
        """Interpreter environments and multicall tools retain their semantic aliases."""

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            target = root / "tool-target"
            target.write_text("tool\n", encoding="utf-8")
            target.chmod(0o700)
            link = root / "tool"
            link.symlink_to(target.name)
            self.assertEqual(
                docs._exact_existing_file(  # pylint: disable=protected-access
                    link, "tool", executable=True, allow_symlink=True
                ), link,
            )
            with mock.patch.object(docs.shutil, "which", return_value=str(link)) as discovery:
                self.assertEqual(docs._discover_tool("doxygen"), target)  # pylint: disable=protected-access
            discovery.assert_called_once_with("doxygen")
            with mock.patch.object(docs.shutil, "which", return_value=str(link)) as discovery:
                self.assertEqual(
                    docs._discover_tool("dot", retain_alias=True), link  # pylint: disable=protected-access
                )
            discovery.assert_called_once_with("dot")
            with mock.patch.object(docs.shutil, "which", return_value=None), self.assertRaisesRegex(
                docs.DocumentationError, "missing: doxygen"
            ):
                docs._discover_tool("doxygen")  # pylint: disable=protected-access
            with self.assertRaisesRegex(docs.DocumentationError, "absolute"):
                docs._exact_existing_file(pathlib.Path("tool"), "tool")  # pylint: disable=protected-access
            with self.assertRaisesRegex(process_owner.DocumentationProcessError, "absolute"):
                process_owner._exact_working_directory(pathlib.Path("."))  # pylint: disable=protected-access

    def test_private_tool_cache_reuses_admitted_bytes_and_cleans_failed_preparation(self) -> None:
        """Only changed inputs rebuild the cache; failed preparation leaves no accepted cache."""

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            source = root / "source"
            output = root / "output"
            (source / "docs").mkdir(parents=True)
            output.mkdir()
            (source / "tooling/environment").mkdir(parents=True)
            (source / "tooling/environment/requirements.lock").write_text("{}\n", encoding="ascii")

            def populate(_source: pathlib.Path, destination: pathlib.Path) -> None:
                """Create the private renderer member that cache admission selects."""

                (destination / "plantuml.jar").write_bytes(b"renderer")

            with mock.patch.object(docs.sys, "platform", "linux"), \
                    mock.patch.object(docs.platform, "machine", return_value="x86_64"), \
                    mock.patch.object(docs, "_populate_tools", side_effect=populate) as prepare, \
                    mock.patch.object(docs, "_validate_python_toolchain", side_effect=lambda _source, python: python), \
                    mock.patch.object(docs, "_validate_plantuml_jar", side_effect=lambda path: path), \
                    mock.patch.object(docs, "_validate_native_diagram_tools", return_value=(
                        pathlib.Path("/usr/bin/java"), pathlib.Path("/usr/bin/dot")
                    )):
                first = docs._prepare_tools(source, output)  # pylint: disable=protected-access
                self.assertEqual(docs._prepare_tools(source, output), first)  # pylint: disable=protected-access
                self.assertEqual(prepare.call_count, 1)
                (source / "tooling/environment/requirements.lock").write_text("changed\n", encoding="ascii")
                docs._prepare_tools(source, output)  # pylint: disable=protected-access
                self.assertEqual(prepare.call_count, 2)
                with mock.patch.object(
                    docs, "_validate_python_toolchain", side_effect=docs.DocumentationError("bad installed package")
                ), self.assertRaisesRegex(docs.DocumentationError, "bad installed package"):
                    docs._prepare_tools(source, output)  # pylint: disable=protected-access
                self.assertEqual(prepare.call_count, 2)
                (output / "tools" / "inputs.sha256").unlink()
                with mock.patch.object(
                    docs, "_populate_tools", side_effect=docs.DocumentationError("failed setup")
                ), self.assertRaisesRegex(docs.DocumentationError, "failed setup"):
                    docs._prepare_tools(source, output)  # pylint: disable=protected-access
                self.assertFalse((output / "tools").exists())

    def test_native_renderer_versions_reject_other_lines_and_prefix_collisions(self) -> None:
        """Host Java and Graphviz must identify the supported renderer prerequisites."""

        good_java = "openjdk 21.0.8 2025-07-15\nOpenJDK Runtime Environment"
        good_dot = "dot - graphviz version 2.43.0 (0)"
        cases = (
            (good_java, good_dot, None),
            ("java 21 2023-09-19", good_dot, None),
            ("openjdk 210.0.8 2025-07-15", good_dot, "Java 21"),
            ("openjdk 22.0.1 2024-04-16", good_dot, "Java 21"),
            ("openjdk 21-ea 2023-07-01", good_dot, "Java 21"),
            (good_java, "dot - graphviz version 2.43.00 (0)", "Graphviz 2.43.0"),
            (good_java, "dot - graphviz version 2.43.0 (0)\nother", "Graphviz 2.43.0"),
        )
        for java_version, dot_version, diagnostic in cases:
            with self.subTest(java=java_version, dot=dot_version), mock.patch.object(
                docs, "_discover_tool", side_effect=[pathlib.Path("/usr/bin/java"), pathlib.Path("/usr/bin/dot")]
            ), mock.patch.object(docs, "_run_small", side_effect=[java_version, dot_version]):
                if diagnostic:
                    with self.assertRaisesRegex(docs.DocumentationError, diagnostic):
                        docs._validate_native_diagram_tools(pathlib.Path.cwd())  # pylint: disable=protected-access
                else:
                    self.assertEqual(
                        docs._validate_native_diagram_tools(pathlib.Path.cwd()),  # pylint: disable=protected-access
                        (pathlib.Path("/usr/bin/java"), pathlib.Path("/usr/bin/dot")),
                    )

    def test_site_publication_is_final_when_stdout_is_unusable(self) -> None:
        """The one public build command finishes with publication and no fallible report."""

        with tempfile.TemporaryDirectory() as directory:
            source, output, product = _create_minimal_documentation_product(pathlib.Path(directory).resolve())
            phases = []

            def render_api(*_args: object) -> None:
                """Record the API phase without executing Doxygen."""

                phases.append("api")

            def render_html(*_args: object) -> None:
                """Record the narrative phase without executing Sphinx."""

                phases.append("html")

            def compose_candidate(_source: pathlib.Path, _output: pathlib.Path, candidate: pathlib.Path) -> None:
                """Supply the complete fixture output for real validation and publication."""

                phases.append("compose")
                shutil.copytree(product, candidate, dirs_exist_ok=True)

            producer_path = source / "tooling/release/documentation/build_documentation.py"
            with mock.patch.object(docs, "__file__", str(producer_path)), \
                    mock.patch.object(docs, "_prepare_tools"), \
                    mock.patch.object(docs, "_discover_tool", return_value=source), \
                    mock.patch.object(docs, "_validate_doxygen", return_value=source), \
                    mock.patch.object(docs, "_build_api", side_effect=render_api), \
                    mock.patch.object(docs, "_build_html", side_effect=render_html), \
                    mock.patch.object(docs, "_compose_site", side_effect=compose_candidate), \
                    mock.patch("builtins.print", side_effect=BrokenPipeError("stdout closed")):
                self.assertEqual(docs.main(["--output-root", str(output)]), 0)
            self.assertEqual(phases, ["api", "html", "compose"])
            docs.verify_site(source, output)

    def test_build_owner_source_locks_reject_indirection(self) -> None:
        """Ordinary verification cannot follow a retargetable source lock."""

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            environment_root = root / "tooling/environment"
            environment_root.mkdir(parents=True)
            target = environment_root / "requirements-target"
            target.write_text("sphinx==1 --hash=sha256:00\n", encoding="utf-8")
            (environment_root / "requirements.lock").symlink_to(target.name)
            with self.assertRaisesRegex(docs.DocumentationError, "exact regular file"):
                docs._parse_python_lock(root)  # pylint: disable=protected-access

    def test_output_root_is_one_exact_direct_directory(self) -> None:
        """The public documentation owner rejects CWD-relative output authority."""

        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory).resolve()
            admitted = docs._admit_output_root(  # pylint: disable=protected-access
                parent / "docs-output"
            )
            self.assertEqual(admitted, parent / "docs-output")
            with self.assertRaisesRegex(docs.DocumentationError, "absolute"):
                docs._admit_output_root(  # pylint: disable=protected-access
                    pathlib.Path("relative-output")
                )
            arguments = ["--output-root", "relative-output"]
            with mock.patch("builtins.print"):
                self.assertEqual(docs.main(arguments), 1)

    def test_html_asset_parser_covers_spacing_and_quote_variants(self) -> None:
        """HTML attribute formatting cannot evade the offline asset gate."""

        source = "<script src = 'https://cdn.example.invalid/tool.js'></script>"
        collect = docs._html_asset_references  # pylint: disable=protected-access
        producer_references, producer_has_base, diagrams = collect(source, {})
        self.assertEqual(
            producer_references,
            ["https://cdn.example.invalid/tool.js"],
        )
        self.assertFalse(producer_has_base)
        self.assertEqual(diagrams, 0)

    def test_offline_asset_contract_pins_each_local_and_external_outcome(self) -> None:
        """Every extraction class is checked against independently authored dispositions."""

        members = {
            "guide/media.ogg",
            "guide/page.css",
            "guide/page.html",
            "guide/pixel.png",
            "guide/vector.svg",
            "shared/font.woff2",
            "shared/theme.css",
        }
        valid_documents = (
            (
                "guide/page.html",
                """
<audio src="media.ogg"></audio>
<img src="data:image/gif;base64,R0lGODlhAQABAIAAAAUEBA==">
<img srcset="pixel.png 1x, data:image/gif;base64,R0lGODlhAQABAIAAAAUEBA== 2x">
<iframe src="?mode=offline#ready"></iframe>
<div style="background:url(pixel.png)"></div>
<style>@import "../shared/theme.css";</style>
<meta http-equiv="refresh" content="0; url=page.html#ready">
<svg><use href="#local-symbol"></use></svg>
<link rel="index" href="#">
""",
            ),
            (
                "guide/page.css",
                '@import "../shared/theme.css"; '
                "a{background:url(pixel.png);src:url(../shared/font.woff2)}"
                '/* url(https://example.invalid/comment.png) */ '
                'a::after { content: "url(https://example.invalid/text.png)"; }',
            ),
            (
                "guide/vector.svg",
                '<image href="pixel.png" style="fill:url(#local-paint)"/>',
            ),
        )
        invalid_documents = (
            (
                "html-attribute-external",
                "guide/page.html",
                '<script src="https://cdn.example.invalid/tool.js"></script>',
                "external",
            ),
            (
                "html-srcset-external",
                "guide/page.html",
                '<img srcset="pixel.png 1x, //cdn.example.invalid/high.png 2x">',
                "external",
            ),
            (
                "html-inline-style-external",
                "guide/page.html",
                '<div style="background:url(https://cdn.example.invalid/bg.png)"></div>',
                "external",
            ),
            (
                "html-style-element-external",
                "guide/page.html",
                '<style>@import "https://cdn.example.invalid/theme.css";</style>',
                "external",
            ),
            (
                "html-meta-refresh-external",
                "guide/page.html",
                '<meta http-equiv="refresh" content="0; url=//example.invalid/page">',
                "external",
            ),
            (
                "css-url-external",
                "guide/page.css",
                "a{background:url(https://cdn.example.invalid/bg.png)}",
                "external",
            ),
            (
                "css-import-external",
                "guide/page.css",
                '@import "//cdn.example.invalid/theme.css";',
                "external",
            ),
            (
                "xml-href-external",
                "guide/vector.svg",
                '<image href="https://cdn.example.invalid/image.png"/>',
                "external",
            ),
            (
                "svg-presentation-variable-external",
                "guide/vector.svg",
                '<svg><style>:root { --paint: url("https://example.invalid/paint.svg"); }</style>'
                '<rect fill="var(--paint)"/></svg>',
                "external",
            ),
            (
                "root-relative",
                "guide/page.html",
                '<script src="/missing.js"></script>',
                "root-relative",
            ),
            (
                "plain-traversal",
                "guide/page.html",
                '<img src="../../outside.png">',
                "escapes the site",
            ),
            (
                "encoded-traversal",
                "guide/page.html",
                '<img src="%2e%2e/%2e%2e/outside.png">',
                "escapes the site",
            ),
            (
                "missing-member",
                "guide/page.html",
                '<link href="missing.css">',
                "missing site member",
            ),
            (
                "malformed-percent",
                "guide/page.html",
                '<img src="bad%GG.png">',
                "malformed encoding",
            ),
            (
                "invalid-utf8",
                "guide/page.html",
                '<img src="%ff.png">',
                "not UTF-8",
            ),
            (
                "backslash",
                "guide/page.html",
                '<img src="..\\outside.png">',
                "forbidden path byte",
            ),
            (
                "nul",
                "guide/page.html",
                '<img src="pixel%00.png">',
                "forbidden path byte",
            ),
            (
                "empty",
                "guide/page.html",
                '<img src="">',
                "empty",
            ),
            (
                "base-element",
                "guide/page.html",
                '<base href="../shared/">',
                "base element",
            ),
        )
        for source, text in valid_documents:
            with self.subTest(valid=source):
                docs._verify_asset_references(source, text, members, {})  # pylint: disable=protected-access
        for case, source, text, diagnostic in invalid_documents:
            with self.subTest(invalid=case), self.assertRaisesRegex(docs.DocumentationError, diagnostic):
                docs._verify_asset_references(source, text, members, {})  # pylint: disable=protected-access

    def test_css_custom_properties_resolve_at_the_consuming_stylesheet(self) -> None:
        """Unused values fetch nothing; consumed variables retain exact URL closure."""

        declarations = (
            ':root { --unused: url("../missing.png"); --image: url("pixel.png?x=1;y=2"); '
            '--alias: var(--image); --remote: url("https://example.invalid/pixel.png"); '
            '--data: url("data:image/gif;base64,R0lGODlhAQABAIAAAAUEBA=="); '
            '--cycle-a: var(--cycle-b); --cycle-b: var(--cycle-a); }'
            '@media (prefers-color-scheme: dark) { :root { --image: url("night.png"); } }'
        )
        properties = docs._collect_css_properties([declarations])  # pylint: disable=protected-access
        members = {"api/nested/pixel.png", "api/nested/night.png"}
        docs._verify_asset_references(  # pylint: disable=protected-access
            "api/theme.css", declarations, members, properties,
        )
        docs._verify_asset_references(  # pylint: disable=protected-access
            "api/nested/page.css", "body { background: var(--alias); mask: var(--data); }", members, properties,
        )
        docs._verify_asset_references(  # pylint: disable=protected-access
            "api/nested/page.html", '<div style="background:var(--alias)"></div>', members, properties,
        )
        for name, diagnostic in (("--unused", "missing site member"), ("--remote", "external")):
            with self.subTest(property=name), self.assertRaisesRegex(docs.DocumentationError, diagnostic):
                docs._verify_asset_references(  # pylint: disable=protected-access
                    "api/nested/page.css", f"body {{ background: var({name}); }}", members, properties,
                )
        self.assertEqual(
            docs._css_asset_references(  # pylint: disable=protected-access
                "body { color: var(--cycle-a); }", properties,
            ),
            [],
        )


class DocumentationPublicationTest(unittest.TestCase):
    """Exercise website publication, source identity, and process-owner closure."""

    def test_completed_site_rejects_stale_source_and_modified_payload(self) -> None:
        """Website verification admits current bytes without tools and rejects source or payload drift."""

        with tempfile.TemporaryDirectory() as directory:
            source, output, product = _create_minimal_documentation_product(pathlib.Path(directory).resolve())
            producer_path = source / "tooling/release/documentation/build_documentation.py"
            with mock.patch.object(docs, "__file__", str(producer_path)), \
                    mock.patch.object(docs, "_prepare_tools") as prepare, \
                    mock.patch.object(docs, "_discover_tool") as discover:
                self.assertEqual(docs.main(["--verify-only", "--output-root", str(output)]), 0)
                prepare.assert_not_called()
                discover.assert_not_called()
            for relative in (
                "docs/README.md", "include/kinetum/api.h", "tooling/release/documentation/build_documentation.py"
            ):
                path = source / relative
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                with self.subTest(source=relative), self.assertRaisesRegex(docs.DocumentationError, "stale"):
                    docs.verify_site(source, output)
                path.write_bytes(original)
            page = product / "README.html"
            original = page.read_bytes()
            page.write_bytes(original + b"\n")
            with self.assertRaisesRegex(docs.DocumentationError, "payload differs"):
                docs.verify_site(source, output)
            page.write_bytes(original)
            added = product / "unrecorded.html"
            added.write_text("<html>unrecorded</html>\n", encoding="ascii")
            with self.assertRaisesRegex(docs.DocumentationError, "payload differs"):
                docs.verify_site(source, output)
            added.unlink()
            manifest = product / "build_manifest.json"
            original = manifest.read_bytes()
            for value in (
                {"source_sha256": "a" * 64},
                {"source_sha256": True, "payload_sha256": "a" * 64},
                {"source_sha256": "A" * 64, "payload_sha256": "b" * 64},
            ):
                manifest.write_text(json.dumps(value), encoding="ascii")
                with self.subTest(manifest=value), self.assertRaisesRegex(docs.DocumentationError, "two exact"):
                    docs.verify_site(source, output)
            manifest.write_bytes(original)
            docs.verify_site(source, output)

    def test_rejected_composition_preserves_the_published_site(self) -> None:
        """Candidate verification finishes before the prior site is replaced."""

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            source = root / "source"
            output = root / "output"
            published = output / "html"
            source.mkdir()
            published.mkdir(parents=True)
            marker = published / "accepted.txt"
            marker.write_text("accepted\n", encoding="utf-8")

            def compose_candidate(
                _source: pathlib.Path, _output: pathlib.Path, destination: pathlib.Path
            ) -> None:
                """Create one candidate that the injected verifier rejects."""

                (destination / "index.html").write_text(
                    "rejected\n", encoding="utf-8"
                )

            with mock.patch.object(
                docs, "_compose_site", side_effect=compose_candidate
            ), mock.patch.object(
                docs,
                "_verify_site_tree",
                side_effect=docs.DocumentationError("rejected candidate"),
            ), self.assertRaisesRegex(docs.DocumentationError, "rejected candidate"):
                docs._compose(source, output, "a" * 64)  # pylint: disable=protected-access

            self.assertEqual(marker.read_text(encoding="utf-8"), "accepted\n")
            self.assertFalse((published / "index.html").exists())

    def test_directory_exchange_publishes_one_complete_candidate(self) -> None:
        """One atomic exchange publishes the candidate and retires the prior tree."""

        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory).resolve()
            published = output / "html"
            published.mkdir()
            (published / "accepted.txt").write_text("old\n", encoding="utf-8")

            def populate(candidate: pathlib.Path) -> None:
                """Populate one complete replacement tree."""

                (candidate / "accepted.txt").write_text("new\n", encoding="utf-8")

            result = publication_owner.replace_directory(output, "html", populate)
            self.assertEqual(result, published)
            self.assertEqual(
                (published / "accepted.txt").read_text(encoding="utf-8"), "new\n"
            )
            self.assertEqual([path.name for path in output.iterdir()], ["html"])

    def test_exchange_failure_preserves_the_accepted_tree(self) -> None:
        """A failed exchange cannot delete or alter the accepted directory."""

        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory).resolve()
            published = output / "html"
            published.mkdir()
            marker = published / "accepted.txt"
            marker.write_text("accepted\n", encoding="utf-8")

            def populate(candidate: pathlib.Path) -> None:
                """Populate one candidate that must not become visible."""

                (candidate / "candidate.txt").write_text("candidate\n", encoding="utf-8")

            with mock.patch.object(
                publication_owner,
                "_exchange_directories",
                side_effect=OSError("exchange failed"),
            ), self.assertRaisesRegex(OSError, "exchange failed"):
                publication_owner.replace_directory(output, "html", populate)

            self.assertEqual(marker.read_text(encoding="utf-8"), "accepted\n")
            self.assertFalse((published / "candidate.txt").exists())
            self.assertEqual([path.name for path in output.iterdir()], ["html"])

    def test_published_validation_failure_restores_the_accepted_tree(self) -> None:
        """A rejected published identity atomically restores the prior tree."""

        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory).resolve()
            published = output / "html"
            published.mkdir()
            marker = published / "accepted.txt"
            marker.write_text("accepted\n", encoding="utf-8")
            rejection = docs.DocumentationError("published identity rejected")

            def populate(candidate: pathlib.Path) -> None:
                """Populate one candidate that fails its published-path check."""

                (candidate / "candidate.txt").write_text("candidate\n", encoding="utf-8")

            def reject_published(_published: pathlib.Path) -> None:
                """Reject the candidate only after it reaches the accepted path."""

                raise rejection

            with self.assertRaises(docs.DocumentationError) as captured:
                publication_owner.replace_directory(
                    output, "html", populate, reject_published
                )

            self.assertIs(captured.exception, rejection)
            self.assertEqual(marker.read_text(encoding="utf-8"), "accepted\n")
            self.assertFalse((published / "candidate.txt").exists())
            self.assertEqual([path.name for path in output.iterdir()], ["html"])

    def test_failed_restoration_retains_both_failure_causes(self) -> None:
        """A restore double fault reports both errors without rewriting either."""

        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory).resolve()
            published = output / "html"
            published.mkdir()
            (published / "accepted.txt").write_text("accepted\n", encoding="utf-8")
            originating = docs.DocumentationError("published identity rejected")
            restoration = OSError("restoration exchange failed")
            real_exchange = publication_owner._exchange_directories  # pylint: disable=protected-access
            exchange_count = 0

            def populate(candidate: pathlib.Path) -> None:
                """Populate one candidate used to enter the restore edge."""

                (candidate / "candidate.txt").write_text("candidate\n", encoding="utf-8")

            def exchange_once(left: pathlib.Path, right: pathlib.Path) -> None:
                """Complete publication and fail only the restoring exchange."""

                nonlocal exchange_count
                exchange_count += 1
                if exchange_count == 1:
                    real_exchange(left, right)
                    return
                raise restoration

            def reject_published(_published: pathlib.Path) -> None:
                """Force restoration after the candidate becomes visible."""

                raise originating

            with mock.patch.object(
                publication_owner, "_exchange_directories", side_effect=exchange_once
            ), self.assertRaises(
                publication_owner.DocumentationPublicationDoubleFault
            ) as captured:
                publication_owner.replace_directory(
                    output, "html", populate, reject_published
                )

            self.assertIs(captured.exception.originating_error, originating)
            self.assertIs(captured.exception.recovery_error, restoration)
            self.assertIn("published identity rejected", str(captured.exception))
            self.assertIn("restoration exchange failed", str(captured.exception))

    def test_first_publication_race_preserves_winner_and_cleans_candidate(self) -> None:
        """A race-created target wins without candidate replacement or residue."""

        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory).resolve()
            published = output / "html"

            def populate(candidate: pathlib.Path) -> None:
                """Populate one complete losing candidate."""

                (candidate / "candidate.txt").write_text("candidate\n", encoding="utf-8")

            def publish_race(
                _candidate: pathlib.Path,
                target: pathlib.Path,
                flags: int,
            ) -> None:
                """Install the competing winner at the kernel publication edge."""

                self.assertEqual(flags, publication_owner.RENAME_NOREPLACE)
                target.mkdir()
                (target / "winner.txt").write_text("winner\n", encoding="utf-8")
                raise FileExistsError("race winner retained the target")

            with mock.patch.object(
                publication_owner,
                "_invoke_renameat2",
                side_effect=publish_race,
            ), self.assertRaisesRegex(FileExistsError, "race winner retained"):
                publication_owner.replace_directory(output, "html", populate)

            self.assertEqual(
                (published / "winner.txt").read_text(encoding="utf-8"), "winner\n"
            )
            self.assertFalse((published / "candidate.txt").exists())
            self.assertEqual([path.name for path in output.iterdir()], ["html"])

    def test_new_publication_rejects_dangling_target_before_population(self) -> None:
        """A dangling target owns its name and prevents candidate construction."""

        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory).resolve()
            target = output / "html"
            target.symlink_to("missing")
            populated = False

            def populate(_candidate: pathlib.Path) -> None:
                """Record an unlawful attempt to start candidate construction."""

                nonlocal populated
                populated = True

            with self.assertRaisesRegex(
                publication_owner.DocumentationPublicationError,
                "must be absent",
            ):
                publication_owner.publish_new_directory(output, "html", populate)

            self.assertFalse(populated)
            self.assertTrue(target.is_symlink())
            self.assertEqual([path.name for path in output.iterdir()], ["html"])

    def test_candidate_cleanup_failure_retains_the_originating_error(self) -> None:
        """A failed rejection cleanup carries both causes in one terminal error."""

        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory).resolve()
            originating = docs.DocumentationError("candidate validation failed")
            cleanup = OSError("candidate cleanup failed")

            def reject_candidate(_candidate: pathlib.Path) -> None:
                """Reject one candidate before publication."""

                raise originating

            with mock.patch.object(
                publication_owner,
                "_remove_exact_directory",
                side_effect=cleanup,
            ), self.assertRaises(
                publication_owner.DocumentationPublicationDoubleFault
            ) as captured:
                publication_owner.replace_directory(
                    output, "html", reject_candidate
                )

            self.assertIs(captured.exception.originating_error, originating)
            self.assertIs(captured.exception.recovery_error, cleanup)
            self.assertIn("candidate validation failed", str(captured.exception))
            self.assertIn("candidate cleanup failed", str(captured.exception))

    def test_internal_source_directory_remains_structurally_rejected(self) -> None:
        """The current public-tree boundary rejects an internal source directory."""

        with tempfile.TemporaryDirectory() as directory:
            source, _output, _product = _create_minimal_documentation_product(
                pathlib.Path(directory).resolve()
            )
            hidden = source / "docs" / "internal"
            hidden.mkdir()
            (hidden / "record.md").write_text("# Record\n", encoding="utf-8")
            with self.assertRaisesRegex(docs.DocumentationError, "forbidden directory"):
                docs._public_markdown_sources(source)  # pylint: disable=protected-access

    def test_final_site_rejects_unpublished_build_artifacts(self) -> None:
        """Only composed API and narrative product members may be published."""

        with tempfile.TemporaryDirectory() as directory:
            source, output, product = _create_minimal_documentation_product(
                pathlib.Path(directory).resolve()
            )
            (product / "README.html").write_text(
                "<html><body>/tmp/kinetum_validation</body></html>\n",
                encoding="utf-8",
            )
            docs._verify_site_tree(  # pylint: disable=protected-access
                source, output, product
            )
            (product / "api" / "index.html").unlink()
            with self.assertRaisesRegex(docs.DocumentationError, "missing api/index.html"):
                docs._verify_site_tree(  # pylint: disable=protected-access
                    source, output, product
                )
            (product / "api" / "index.html").write_text(
                "<html><body>Doxygen API</body></html>\n", encoding="utf-8"
            )
            downloaded = product / "_downloads" / "copied-page" / "index.html"
            downloaded.parent.mkdir(parents=True)
            downloaded.write_text(f"<html><body>{output}</body></html>\n", encoding="utf-8")
            with self.assertRaisesRegex(docs.DocumentationError, "forbidden path"):
                docs._verify_site_tree(  # pylint: disable=protected-access
                    source, output, product
                )
            downloaded.unlink()
            for name in ("requirements.lock", "plantuml.jar", "build-requirements.lock", "_plantuml/cache.svg"):
                private = product / name
                private.parent.mkdir(parents=True, exist_ok=True)
                private.write_text("source only\n", encoding="utf-8")
                with self.subTest(name=name), self.assertRaisesRegex(docs.DocumentationError, "source-only"):
                    docs._verify_site_tree(  # pylint: disable=protected-access
                        source, output, product
                    )
                private.unlink()

    def test_documentation_process_owner_bounds_output_and_time(self) -> None:
        """The documentation process owner bounds work and retires descendants."""

        observed = process_owner.run_captured(
            [
                sys.executable,
                "-I",
                "-c",
                "import os;print(int(os.getpid()==os.getpgrp()))",
            ],
            timeout_seconds=2,
            output_limit_bytes=32,
            working_directory=pathlib.Path.cwd().resolve(),
        )
        self.assertEqual(observed.returncode, 0)
        self.assertEqual(observed.output.strip(), b"1")

        with self.assertRaisesRegex(
            process_owner.DocumentationProcessError, "excessive output"
        ) as excessive:
            process_owner.run_captured(
                [sys.executable, "-I", "-c", "import os;os.write(1,b'x'*4096)"],
                timeout_seconds=2,
                output_limit_bytes=32,
                working_directory=pathlib.Path.cwd().resolve(),
            )
        self.assertEqual(excessive.exception.output, b"x" * 32)
        with self.assertRaisesRegex(
            process_owner.DocumentationProcessError, "timed out"
        ):
            process_owner.run_captured(
                [sys.executable, "-I", "-c", "import time;time.sleep(10)"],
                timeout_seconds=0.05,
                output_limit_bytes=32,
                working_directory=pathlib.Path.cwd().resolve(),
            )

        descendant_program = (
            "import os,subprocess,sys,time;"
            "subprocess.Popen([sys.executable,'-I','-c',"
            "'import time;time.sleep(30)'],stdout=subprocess.DEVNULL,"
            "stderr=subprocess.DEVNULL);"
            "os.write(1,(str(os.getpid())+'\\n').encode())"
        )
        real_killpg = os.killpg
        captured_kills: list[int] = []

        def record_captured_kill(group_id: int, signal_number: int) -> None:
            """Record the captured runner's sole group-kill operation."""
            if signal_number == process_owner.signal.SIGKILL:
                captured_kills.append(group_id)
            real_killpg(group_id, signal_number)

        with mock.patch.object(
            process_owner.os,
            "killpg",
            side_effect=record_captured_kill,
        ), self.assertRaisesRegex(
            process_owner.DocumentationProcessError, "live descendant"
        ) as descendant:
            process_owner.run_captured(
                [sys.executable, "-I", "-c", descendant_program],
                timeout_seconds=2,
                output_limit_bytes=32,
                working_directory=pathlib.Path.cwd().resolve(),
            )
        group_id = int(descendant.exception.output.strip())
        self.assertEqual(captured_kills, [group_id])
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.killpg(group_id, 0)
            except ProcessLookupError:
                break
            time.sleep(0.01)
        else:
            self.fail("documentation command descendant group survived cleanup")

        with tempfile.TemporaryDirectory() as temporary:
            group_file = pathlib.Path(temporary) / "visible-group"
            visible_program = (
                "import os,subprocess,sys;"
                "subprocess.Popen([sys.executable,'-I','-c',"
                "'import time;time.sleep(30)'],stdout=subprocess.DEVNULL,"
                "stderr=subprocess.DEVNULL);"
                f"open({str(group_file)!r},'w',encoding='ascii').write(str(os.getpid()))"
            )
            visible_kills: list[int] = []

            def record_visible_kill(
                visible_group_id: int,
                signal_number: int,
            ) -> None:
                """Record the visible runner's sole group-kill operation."""
                if signal_number == process_owner.signal.SIGKILL:
                    visible_kills.append(visible_group_id)
                real_killpg(visible_group_id, signal_number)

            with mock.patch.object(
                process_owner.os,
                "killpg",
                side_effect=record_visible_kill,
            ), self.assertRaisesRegex(
                process_owner.DocumentationProcessError,
                "live descendant",
            ):
                process_owner.run_visible(
                    [sys.executable, "-I", "-c", visible_program],
                    timeout_seconds=2,
                    working_directory=pathlib.Path.cwd().resolve(),
                )
            visible_group_id = int(group_file.read_text(encoding="ascii"))
            self.assertEqual(visible_kills, [visible_group_id])
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    os.killpg(visible_group_id, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.01)
            else:
                self.fail(
                    "visible documentation command descendant group survived cleanup"
                )

    def test_builder_staging_and_python_reproducibility_pins_are_exact(self) -> None:
        """Builders require distinct staging and the exact Python 3.12 venv closure."""

        self.assertEqual(
            {docs.HTML_SOURCE_TREE, docs.LINKCHECK_SOURCE_TREE},
            {"html-source", "linkcheck-source"},
        )
        with mock.patch.object(docs.sys, "version_info", (3, 12, 3)):
            docs._require_running_python()  # pylint: disable=protected-access
        for version in ((3, 11, 9), (3, 13, 0)):
            with self.subTest(version=version), mock.patch.object(
                docs.sys, "version_info", version
            ), self.assertRaisesRegex(docs.DocumentationError, "exactly Python 3.12"):
                docs._require_running_python()  # pylint: disable=protected-access

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            (root / "tooling/environment").mkdir(parents=True)
            packages = [
                ["sphinx", "8.1.3"],
                ["myst-parser", "4.0.1"],
                ["sphinx-rtd-theme", "3.1.0"],
                ["sphinxcontrib-plantuml", "0.31"],
            ]
            (root / "tooling/environment/requirements.lock").write_text(
                "sphinx==8.1.3\nmyst-parser==4.0.1\n"
                "sphinx-rtd-theme==3.1.0\nsphinxcontrib-plantuml==0.31\n",
                encoding="ascii",
            )
            python = root / "venv" / "bin" / "python3.12"
            python.parent.mkdir(parents=True)
            python.write_text("", encoding="ascii")
            python.chmod(0o700)
            observed = {
                "python": [3, 12, 3],
                "prefix": str(root / "venv"),
                "base_prefix": "/usr",
                "packages": packages,
            }
            with mock.patch.object(docs, "_run_small", return_value=json.dumps(observed)):
                self.assertEqual(
                    docs._validate_python_toolchain(root, python),  # pylint: disable=protected-access
                    python,
                )
            invalid = (
                ({"python": [3, 11, 9]}, "supported 3.12 line"),
                ({"python": [3, 13, 0]}, "supported 3.12 line"),
                ({"python": "3.12.3"}, "supported 3.12 line"),
                ({"prefix": "/usr"}, "own virtual environment"),
                ({"base_prefix": str(root / "venv")}, "own virtual environment"),
                ({"packages": [["sphinx", ""], *packages[1:]]}, "package row is malformed"),
                ({"packages": packages[1:]}, "package mismatch"),
                ({"packages": [["sphinx", "8.1.2"], *packages[1:]]}, "package mismatch"),
                ({"packages": [*packages, ["unowned-package", "1.0"]]}, "undeclared packages"),
            )
            for changes, diagnostic in invalid:
                with self.subTest(changes=changes), mock.patch.object(
                    docs, "_run_small", return_value=json.dumps({**observed, **changes})
                ), self.assertRaisesRegex(docs.DocumentationError, diagnostic):
                    docs._validate_python_toolchain(root, python)  # pylint: disable=protected-access

    def test_redistributed_standard_license_texts_are_upstream_exact(self) -> None:
        """Standard license copies retain their exact verified upstream bytes."""

        source_root = pathlib.Path(__file__).resolve().parents[2]
        expected = {
            "LICENSE": "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
            "third_party/documentation/licenses/JQUERY_MIT.txt": (
                "d4db9ebe6f29f5168eac45ad713f055623ac5d0dcd5ba92da23d650ae012020d"
            ),
            "third_party/documentation/licenses/PYGMENTS_BSD_2_CLAUSE.txt": (
                "a9d66f1d526df02e29dce73436d34e56e8632f46c275bbdffc70569e882f9f17"
            ),
            "third_party/documentation/licenses/SPHINX_BSD_2_CLAUSE.txt": (
                "b8bd9eb4bf4925a0cb788aacd479bb64daa8e00b2830eff75a2173bdcdb3baed"
            ),
            "third_party/documentation/licenses/SPHINX_RTD_THEME_MIT.txt": (
                "4864896421b8a49112eefa899a6b4366329bd6fe669f38efefb29f81487cef1e"
            ),
        }
        for relative, digest in expected.items():
            with self.subTest(relative=relative):
                path = source_root / relative
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_private_venv_and_staged_configuration_keep_their_real_locations(self) -> None:
        """Staged configuration preserves tool identity and renders API navigation without downloads."""

        with tempfile.TemporaryDirectory() as directory:
            source, output, _product = _create_minimal_documentation_product(pathlib.Path(directory).resolve())
            actual_source = pathlib.Path(__file__).resolve().parents[2]
            (source / "docs/conf.py").write_bytes((actual_source / "docs/conf.py").read_bytes())
            for name in ("_static", "_templates"):
                shutil.copytree(actual_source / "docs" / name, source / "docs" / name)
            (source / "docs" / "README.md").write_text(
                "# Docs\n[Flow](diagrams/ordered_cut_boundary_protocol.md)\n"
                "[Release](../CHANGELOG.md)\n[Modules](../src/modules/README.md)\n", encoding="ascii"
            )
            venv_root = output / "tools" / "venv"
            venv.EnvBuilder(symlinks=True).create(venv_root)
            site = venv_root / "lib" / "python3.12" / "site-packages"
            (site / "environment_marker.py").write_text('VALUE = "venv-local-import"\n', encoding="ascii")
            tools = docs._DocumentationTools(  # pylint: disable=protected-access
                venv_root / "bin" / "python3.12", pathlib.Path("/exact tool's directory/java"),
                pathlib.Path("/exact PlantUML/plantuml.jar"), pathlib.Path("/exact/graphviz/dot"),
            )
            staged = docs._stage_for_sphinx(source, output, "html-source", tools)  # pylint: disable=protected-access
            observed = process_owner.run_captured(
                [str(tools.python), "-I", "-B", "-c",
                 "import environment_marker,json,runpy,sys;facts=runpy.run_path(sys.argv[1]);"
                 "print(json.dumps([list(sys.version_info[:2]),sys.prefix,sys.base_prefix,"
                 "environment_marker.VALUE,facts['plantuml'],facts['plantuml_output_format'],"
                 "facts['plantuml_cache_path']]))", str(staged / "conf.py")],
                timeout_seconds=2, output_limit_bytes=4096, working_directory=output,
            )
            self.assertEqual(observed.returncode, 0, observed.output)
            version, prefix, base_prefix, marker, command, image_format, cache_path = json.loads(observed.output)
            self.assertEqual(version, [3, 12])
            self.assertEqual(prefix, str(venv_root))
            self.assertNotEqual(prefix, base_prefix)
            self.assertEqual(marker, "venv-local-import")
            self.assertEqual(
                command,
                [str(tools.java), "-Djava.awt.headless=true", "-DPLANTUML_SECURITY_PROFILE=SANDBOX",
                 "-jar", str(tools.plantuml), "-graphvizdot", str(tools.dot)],
            )
            self.assertEqual(image_format, "svg_img")
            self.assertEqual(cache_path, str(staged / "_plantuml"))

            rendered = output / "narrative"
            sphinx = process_owner.run_captured(
                docs._sphinx_command(  # pylint: disable=protected-access
                    pathlib.Path(sys.executable), "html", staged, rendered, output / "doctrees",
                ),
                timeout_seconds=30, output_limit_bytes=64 * 1024, working_directory=output,
                environment=docs._build_environment(),  # pylint: disable=protected-access
            )
            self.assertEqual(sphinx.returncode, 0, sphinx.output)
            index = (rendered / "README.html").read_text(encoding="utf-8")
            self.assertIn('<a href="api/index.html"><code>api/index.html</code></a>', index)
            self.assertFalse((rendered / "api").exists())
            self.assertFalse(any((rendered / "_downloads").rglob("*")))
