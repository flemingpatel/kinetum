#!/usr/bin/env -S python3 -I -B
"""Build or verify Kinetum's independently published documentation website.

The source tree keeps human-readable Markdown. This owner stages only the
public document graph, derives Sphinx's hidden toctree from the links in the
canonical documentation index, invokes exact build tools without a shell, and
composes narrative and public-header API output into one self-contained site. Locked
rendering dependencies are prepared in a private build cache; no CMake build
or caller-managed virtual environment is required.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import html
import importlib.util
import json
import math
import os
import pathlib
import platform
import posixpath
import re
import shutil
import sys
import urllib.parse
from collections import deque
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any


SPHINX_VERSION = "8.1.3"
MYST_PARSER_VERSION = "4.0.1"
SPHINX_RTD_THEME_VERSION = "3.1.0"
SPHINX_PLANTUML_VERSION = "0.31"
PLANTUML_VERSION = "1.2026.8"
PLANTUML_SHA256 = "5e1ecfa8ecd32c90b03bbf3b1eb6f020943f98ab0fcf4032be31a0002ee2c462"
PLANTUML_JAR_LIMIT_BYTES = 64 * 1024 * 1024
DOXYGEN_VERSION = "1.9.8"
BUILD_MANIFEST = "build_manifest.json"

HTML_SOURCE_TREE = "html-source"
LINKCHECK_SOURCE_TREE = "linkcheck-source"
DOCUMENTATION_SOURCE_ONLY_MEMBERS = frozenset(
    {
        "_kinetum_docs.json",
        "Doxyfile.in",
        "conf.py",
        "plantuml.jar",
        "build-requirements.lock",
        "requirements.lock",
    }
)

COMMAND_TIMEOUT_SECONDS = 30
BUILD_TIMEOUT_SECONDS = 15 * 60
COMMAND_OUTPUT_LIMIT_BYTES = 64 * 1024
DOCUMENTATION_JSON_LIMIT_BYTES = 16 * 1024 * 1024
MARKDOWN_LINK_RE = re.compile(r"(?P<prefix>\]\()(?P<target>[^)\s]+)(?P<suffix>[^)]*\))")
PLANTUML_IMAGE_RE = re.compile(r"plantuml-[0-9a-f]{40}\.svg")
CSS_URL_RE = re.compile(r"url\(\s*['\"]?(?P<url>[^)'\"]+)", re.IGNORECASE)
CSS_IMPORT_RE = re.compile(
    r"@import\s+(?:url\(\s*)?['\"]?(?P<url>[^)'\";\s]+)", re.IGNORECASE
)
CSS_LITERAL_RE = re.compile(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|/\*.*?\*/''', re.DOTALL)
CSS_PROPERTY_RE = re.compile(r"(?<![\w-])(?P<name>--[\w-]+)\s*:")
CSS_VARIABLE_RE = re.compile(r"\bvar\s*\(\s*(?P<name>--[\w-]+)", re.IGNORECASE)
META_REFRESH_URL_RE = re.compile(
    r"(?:^|;)\s*url\s*=\s*['\"]?(?P<url>[^'\";]+)", re.IGNORECASE
)
XML_ASSET_RE = re.compile(
    r"(?:href|src)\s*=\s*['\"](?P<url>[^'\"]+)", re.IGNORECASE
)
LOCK_REQUIREMENT_RE = re.compile(r"^([a-z0-9][a-z0-9._-]*)==([^\s\\]+)", re.IGNORECASE)

ASSET_TAG_ATTRIBUTES = {
    "audio": {"src"},
    "base": {"href"},
    "embed": {"src"},
    "iframe": {"src"},
    "image": {"href", "xlink:href"},
    "img": {"src", "srcset"},
    "input": {"src"},
    "link": {"href"},
    "object": {"data"},
    "script": {"src"},
    "source": {"src", "srcset"},
    "track": {"src"},
    "use": {"href", "xlink:href"},
    "video": {"poster", "src"},
}
SVG_CSS_ASSET_ATTRIBUTES = frozenset({
    "fill", "stroke", "filter", "clip-path", "mask", "cursor",
    "marker", "marker-start", "marker-mid", "marker-end",
})


def _mask_css_literal(match: re.Match[str]) -> str:
    """Hide quoted values and comments while preserving source offsets."""

    return " " * len(match.group())


def _css_properties(text: str) -> tuple[str, dict[str, list[str]]]:
    """Separate custom-property token values from ordinary CSS declarations.

    Quoted strings, comments, and balanced value blocks cannot terminate a
    declaration. Returned values remain unresolved until a var() use site.
    """

    masked = CSS_LITERAL_RE.sub(_mask_css_literal, text)
    properties: dict[str, list[str]] = {}
    pieces = []
    previous = 0
    closing = {"(": ")", "[": "]", "{": "}"}
    for match in CSS_PROPERTY_RE.finditer(masked):
        if match.start() < previous:
            continue
        position = match.end()
        nesting = []
        while position < len(masked):
            character = masked[position]
            if not nesting and character in ";}":
                break
            if character in closing:
                nesting.append(closing[character])
            elif character in ")]}":
                if not nesting or character != nesting.pop():
                    raise DocumentationError("generated CSS custom property has unbalanced delimiters")
            position += 1
        if nesting:
            raise DocumentationError("generated CSS custom property has an unterminated value")
        properties.setdefault(match.group("name"), []).append(text[match.end():position])
        pieces.extend((text[previous:match.start()], " " * (position - match.start())))
        previous = position
    pieces.append(text[previous:])
    return "".join(pieces), properties


def _collect_css_properties(texts: Iterable[str]) -> dict[str, list[str]]:
    """Retain every declared value, including alternate theme/media values."""

    properties: dict[str, list[str]] = {}
    for text in texts:
        _, declarations = _css_properties(text)
        for name, values in declarations.items():
            properties.setdefault(name, []).extend(values)
    return properties


def _css_references(text: str, properties: dict[str, list[str]]) -> list[str]:
    """Collect literal URLs and reachable variable URLs at this CSS use site.

    Custom properties alone do not fetch resources. Their relative URLs take
    the consuming stylesheet or document as their base. Follow each variable
    once and check every possible declared value without selecting a theme.
    """

    ordinary, local = _css_properties(text)
    definitions = dict(properties)
    for name, values in local.items():
        definitions[name] = [*properties.get(name, []), *values]
    pending = [ordinary]
    visited: set[str] = set()
    references = []
    while pending:
        value = pending.pop()
        masked = CSS_LITERAL_RE.sub(_mask_css_literal, value)
        for pattern in (CSS_URL_RE, CSS_IMPORT_RE):
            references.extend(
                match.group("url").strip() for match in pattern.finditer(value)
                if not masked[match.start()].isspace()
            )
        for match in CSS_VARIABLE_RE.finditer(masked):
            name = match.group("name")
            if name not in visited:
                visited.add(name)
                pending.extend(definitions.get(name, []))
    return references


def _srcset_references(value: str) -> list[str]:
    """Extract candidate URLs using the HTML srcset comma/descriptor states."""

    references: list[str] = []
    position = 0
    while position < len(value):
        while position < len(value) and (value[position].isspace() or value[position] == ","):
            position += 1
        if position == len(value):
            break
        begin = position
        while position < len(value) and not value[position].isspace():
            position += 1
        reference = value[begin:position]
        if reference.endswith(","):
            reference = reference.rstrip(",")
            if reference:
                references.append(reference)
            continue
        references.append(reference)
        parenthesis_depth = 0
        while position < len(value):
            character = value[position]
            position += 1
            if character == "(":
                parenthesis_depth += 1
            elif character == ")" and parenthesis_depth > 0:
                parenthesis_depth -= 1
            elif character == "," and parenthesis_depth == 0:
                break
    return references


class DocumentationError(RuntimeError):
    """Report one documentation ownership or build-contract violation."""


def _reject_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build one object while rejecting duplicate member names."""

    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _finite_json_float(value: str) -> float:
    """Parse one JSON float only when its binary value remains finite."""

    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite JSON number")
    return parsed


def _reject_json_constant(_value: str) -> None:
    """Reject Python's non-standard JSON constants."""

    raise ValueError("non-finite JSON constant")


def _validate_json_text(value: Any) -> None:
    """Reject decoded strings that cannot be represented as strict UTF-8."""

    if isinstance(value, str):
        value.encode("utf-8", errors="strict")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_text(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            key.encode("utf-8", errors="strict")
            _validate_json_text(item)


def _parse_json_object(raw: str, role: str) -> dict[str, Any]:
    """Parse one bounded unambiguous JSON text document with an object root."""

    try:
        if not isinstance(raw, str):
            raise TypeError("JSON input is not text")
        if not raw or len(raw) > DOCUMENTATION_JSON_LIMIT_BYTES:
            raise ValueError("empty or oversized JSON")
        encoded = raw.encode("utf-8", errors="strict")
        if len(encoded) > DOCUMENTATION_JSON_LIMIT_BYTES:
            raise ValueError("oversized JSON")
        result = json.loads(
            raw,
            object_pairs_hook=_reject_json_pairs,
            parse_constant=_reject_json_constant,
            parse_float=_finite_json_float,
        )
        _validate_json_text(result)
    except (
        json.JSONDecodeError,
        MemoryError,
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as error:
        raise DocumentationError(f"{role} is not exact JSON") from error
    if not isinstance(result, dict):
        raise DocumentationError(f"{role} does not have an object root")
    return result


def _load_process_owner() -> Any:
    """Load the exact sibling process owner without ambient import search."""

    path = pathlib.Path(__file__).absolute().with_name("documentation_process.py")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise DocumentationError("documentation process owner is unavailable") from error
    if path != resolved or not resolved.is_file():
        raise DocumentationError("documentation process owner must be one direct source file")
    module_name = "_kinetum_documentation_process"
    existing = sys.modules.get(module_name)
    if existing is not None:
        existing_path = getattr(existing, "__file__", None)
        if not isinstance(existing_path, str) or pathlib.Path(existing_path).resolve(strict=True) != resolved:
            raise DocumentationError("documentation process-owner module identity changed")
        return existing
    spec = importlib.util.spec_from_file_location(module_name, resolved)
    if spec is None or spec.loader is None:
        raise DocumentationError("documentation process owner cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[module_name]
        raise
    return module


DOCUMENTATION_PROCESS = _load_process_owner()


def _load_publication_owner() -> Any:
    """Load the exact sibling directory-publication owner without import search."""

    path = pathlib.Path(__file__).absolute().with_name("documentation_publication.py")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise DocumentationError("documentation publication owner is unavailable") from error
    if path != resolved or not resolved.is_file():
        raise DocumentationError(
            "documentation publication owner must be one direct source file"
        )
    module_name = "_kinetum_documentation_publication"
    existing = sys.modules.get(module_name)
    if existing is not None:
        existing_path = getattr(existing, "__file__", None)
        if (
            not isinstance(existing_path, str)
            or pathlib.Path(existing_path).resolve(strict=True) != resolved
        ):
            raise DocumentationError(
                "documentation publication-owner module identity changed"
            )
        return existing
    spec = importlib.util.spec_from_file_location(module_name, resolved)
    if spec is None or spec.loader is None:
        raise DocumentationError("documentation publication owner cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[module_name]
        raise
    return module


DOCUMENTATION_PUBLICATION = _load_publication_owner()


class _AssetReferenceParser(HTMLParser):
    """Collect page-time asset references from one generated HTML page."""

    def __init__(self) -> None:
        """Initialize one strict attribute collector."""

        super().__init__(convert_charrefs=True)
        self.references: list[str] = []
        self.styles: list[str] = []
        self._style_depth = 0
        self.has_base = False
        self.plantuml_images = 0

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        """Collect relevant attributes from one ordinary start tag."""

        if tag.lower() == "style":
            self._style_depth += 1
        self._collect(tag, attrs)

    def handle_startendtag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        """Collect relevant attributes from one self-closing start tag."""

        self._collect(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        """Close one inline stylesheet without accepting malformed nesting."""

        if tag.lower() == "style" and self._style_depth > 0:
            self._style_depth -= 1

    def handle_data(self, data: str) -> None:
        """Collect page-time references from inline stylesheet contents."""

        if self._style_depth:
            self.styles.append(data)

    def _collect(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Append every page-time reference owned by `tag`."""

        normalized_tag = tag.lower()
        if normalized_tag == "base":
            self.has_base = True
        selected = ASSET_TAG_ATTRIBUTES.get(normalized_tag, set())
        normalized_attrs = {
            name.lower(): value for name, value in attrs if value is not None
        }
        if normalized_tag == "img" and PLANTUML_IMAGE_RE.fullmatch(
            posixpath.basename(normalized_attrs.get("src", ""))
        ):
            self.plantuml_images += 1
        for name, value in attrs:
            if value is None:
                continue
            normalized_name = name.lower()
            if normalized_name in selected:
                if normalized_name == "srcset":
                    self.references.extend(_srcset_references(value))
                else:
                    self.references.append(value)
            if normalized_name == "style":
                self.styles.append(value)
            elif normalized_name in SVG_CSS_ASSET_ATTRIBUTES:
                self.styles.append(f"{normalized_name}: {value};")
        if (
            normalized_tag == "meta"
            and normalized_attrs.get("http-equiv", "").lower() == "refresh"
        ):
            content = normalized_attrs.get("content", "")
            match = META_REFRESH_URL_RE.search(content)
            if match is not None:
                self.references.append(match.group("url").strip())


def _canonical_package_name(value: str) -> str:
    """Return the Python packaging canonical form without importing packaging."""

    return re.sub(r"[-_.]+", "-", value).lower()


def _exact_existing_directory(path: pathlib.Path, role: str) -> pathlib.Path:
    """Resolve one explicit existing direct directory and return its identity."""

    if not path.is_absolute():
        raise DocumentationError(f"{role} must be absolute: {path}")
    absolute = path.absolute()
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise DocumentationError(f"{role} is unavailable: {path}") from error
    if absolute != resolved or not resolved.is_dir():
        raise DocumentationError(f"{role} must be one exact directory: {path}")
    return resolved


def _exact_existing_file(
    path: pathlib.Path, role: str, *, executable: bool = False, allow_symlink: bool = False
) -> pathlib.Path:
    """Require one regular file and retain an allowed semantic launch alias."""

    if not path.is_absolute():
        raise DocumentationError(f"{role} must be absolute: {path}")
    absolute = path.absolute()
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise DocumentationError(f"{role} is unavailable: {path}") from error
    if (not allow_symlink and absolute != resolved) or not resolved.is_file():
        raise DocumentationError(f"{role} must be one exact regular file: {path}")
    if executable and not os.access(resolved, os.X_OK):
        raise DocumentationError(f"{role} is not executable: {path}")
    return absolute if allow_symlink else resolved


def _admit_output_root(path: pathlib.Path, *, create: bool = True) -> pathlib.Path:
    """Admit, and optionally create, one exact direct documentation output."""

    if not path.is_absolute() or not path.name or path.name in {".", ".."}:
        raise DocumentationError("documentation output root must be one absolute path atom")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", path.name):
        raise DocumentationError("documentation output root name is not canonical")
    absolute = path.absolute()
    if absolute != path or absolute == pathlib.Path("/"):
        raise DocumentationError("documentation output root is not lexically exact")
    parent = _exact_existing_directory(absolute.parent, "documentation output parent")
    if absolute.parent != parent:
        raise DocumentationError("documentation output parent identity changed")
    if create:
        try:
            absolute.mkdir()
        except FileExistsError:
            pass
    return _exact_existing_directory(absolute, "documentation output root")


def _run_small(
    command: Sequence[str], role: str, working_directory: pathlib.Path
) -> str:
    """Run one bounded metadata command and return strict UTF-8 output."""

    try:
        completed = DOCUMENTATION_PROCESS.run_captured(
            command,
            timeout_seconds=COMMAND_TIMEOUT_SECONDS,
            output_limit_bytes=COMMAND_OUTPUT_LIMIT_BYTES,
            working_directory=working_directory,
            environment=_build_environment(),
        )
    except DOCUMENTATION_PROCESS.DocumentationProcessError as error:
        raise DocumentationError(f"{role} could not execute: {error}") from error
    try:
        output = completed.output.decode("utf-8", errors="strict").strip()
    except UnicodeError as error:
        raise DocumentationError(f"{role} produced non-UTF-8 output") from error
    if completed.returncode != 0:
        raise DocumentationError(f"{role} failed: {output[:4096]}")
    return output


def _run_build(
    command: Sequence[str],
    role: str,
    environment: dict[str, str],
    working_directory: pathlib.Path,
) -> None:
    """Run one exact build command under the shared wall-clock bound."""

    try:
        completed = DOCUMENTATION_PROCESS.run_visible(
            command,
            timeout_seconds=BUILD_TIMEOUT_SECONDS,
            working_directory=working_directory,
            environment=environment,
        )
    except DOCUMENTATION_PROCESS.DocumentationProcessError as error:
        raise DocumentationError(f"{role} could not execute: {error}") from error
    if completed.returncode != 0:
        raise DocumentationError(f"{role} failed with status {completed.returncode}")


def _read_text(path: pathlib.Path, role: str) -> str:
    """Read one exact UTF-8 text file."""

    try:
        with path.open("r", encoding="utf-8", errors="strict", newline="") as stream:
            return stream.read()
    except (OSError, UnicodeError) as error:
        raise DocumentationError(f"{role} is not readable UTF-8: {path}") from error


def _require_running_python() -> None:
    """Require the documentation owner's exact reproducibility interpreter line."""

    if sys.version_info[:2] != (3, 12):
        raise DocumentationError("documentation commands require exactly Python 3.12")


def _read_version(source_root: pathlib.Path) -> str:
    """Read the repository's sole canonical product version."""

    version_path = _exact_existing_file(source_root / "VERSION", "source VERSION")
    value = _read_text(version_path, "source VERSION")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?\n", value):
        raise DocumentationError("source VERSION is not one canonical newline-terminated value")
    return value[:-1]


def _parse_python_lock(source_root: pathlib.Path) -> dict[str, str]:
    """Parse the exact package/version membership from the hashed Python lock."""

    lock_path = _exact_existing_file(
        source_root / "tooling" / "environment" / "requirements.lock", "Python dependency lock"
    )
    expected: dict[str, str] = {}
    for line in _read_text(lock_path, "documentation Python lock").splitlines():
        match = LOCK_REQUIREMENT_RE.match(line)
        if match is None:
            continue
        name = _canonical_package_name(match.group(1))
        if name in expected:
            raise DocumentationError(f"duplicate Python lock entry: {name}")
        expected[name] = match.group(2)
    if not expected:
        raise DocumentationError("documentation Python lock has no package entries")
    return expected


def _validate_python_toolchain(
    source_root: pathlib.Path, docs_python: pathlib.Path
) -> pathlib.Path:
    """Require a Python 3.12 venv with the exact lock and retain its launch path."""

    docs_python = _exact_existing_file(
        docs_python, "documentation Python", executable=True, allow_symlink=True
    )
    probe = (
        "import importlib.metadata as m,json,sys;"
        "print(json.dumps({'python':list(sys.version_info[:3]),"
        "'prefix':sys.prefix,'base_prefix':sys.base_prefix,"
        "'packages':[[d.metadata['Name'],d.version] for d in m.distributions() "
        "if d.metadata.get('Name')]}))"
    )
    output = _run_small(
        [str(docs_python), "-I", "-B", "-c", probe],
        "documentation Python probe",
        source_root,
    )
    observed = _parse_json_object(
        output,
        "documentation Python probe",
    )
    if set(observed) != {"python", "prefix", "base_prefix", "packages"}:
        raise DocumentationError("documentation Python probe returned unknown fields")
    version = observed["python"]
    if (
        not isinstance(version, list)
        or len(version) != 3
        or any(not isinstance(part, int) or isinstance(part, bool) or part < 0 for part in version)
        or version[:2] != [3, 12]
    ):
        raise DocumentationError("documentation Python must be exactly the supported 3.12 line")
    if (
        observed["prefix"] != str(docs_python.parent.parent)
        or not isinstance(observed["base_prefix"], str)
        or not observed["base_prefix"]
        or observed["prefix"] == observed["base_prefix"]
    ):
        raise DocumentationError("documentation Python must execute inside its own virtual environment")

    expected = _parse_python_lock(source_root)
    packages = observed["packages"]
    if not isinstance(packages, list):
        raise DocumentationError("documentation Python package observation is malformed")
    actual: dict[str, str] = {}
    for package in packages:
        if (
            not isinstance(package, list)
            or len(package) != 2
            or not all(isinstance(value, str) and value for value in package)
        ):
            raise DocumentationError("installed Python package row is malformed")
        name, version = package
        canonical = _canonical_package_name(name)
        if canonical in actual:
            raise DocumentationError(f"duplicate installed Python package: {canonical}")
        actual[canonical] = version
    for name, version in expected.items():
        if actual.get(name) != version:
            raise DocumentationError(
                f"documentation Python package mismatch: {name} must be {version}"
            )
    unexpected = set(actual) - set(expected) - {"pip"}
    if unexpected:
        raise DocumentationError(
            "documentation Python environment contains undeclared packages: "
            + ", ".join(sorted(unexpected))
        )

    direct = {
        "sphinx": SPHINX_VERSION,
        "myst-parser": MYST_PARSER_VERSION,
        "sphinx-rtd-theme": SPHINX_RTD_THEME_VERSION,
        "sphinxcontrib-plantuml": SPHINX_PLANTUML_VERSION,
    }
    for name, version in direct.items():
        if expected.get(name) != version:
            raise DocumentationError(f"documentation lock changed its direct {name} pin")
    return docs_python


def _validate_native_diagram_tools(source_root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    """Admit the host Java 21 runtime and Graphviz before preparing render tools."""

    java = _discover_tool("java")
    # Ubuntu's dot alias selects layout mode in libgvc6-config-update.
    dot = _discover_tool("dot", retain_alias=True)
    java_version = _run_small([str(java), "--version"], "Java version", source_root)
    if not re.match(r'^(?:openjdk|java) 21(?:\.[0-9]+){0,3}(?:[ +\n]|$)', java_version):
        raise DocumentationError("documentation rendering requires Java 21")
    dot_version = _run_small([str(dot), "-V"], "Graphviz version", source_root)
    if not re.fullmatch(r"dot - graphviz version 2\.43\.0 \([^\r\n]+\)", dot_version):
        raise DocumentationError("documentation rendering requires Graphviz 2.43.0")
    return java, dot


def _validate_plantuml_jar(path: pathlib.Path) -> pathlib.Path:
    """Require the bounded, source-pinned renderer bytes before Java may load them."""

    path = _exact_existing_file(path, "PlantUML JAR")
    if path.stat().st_size > PLANTUML_JAR_LIMIT_BYTES:
        raise DocumentationError("PlantUML JAR exceeds its byte bound")
    with path.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != PLANTUML_SHA256:
            raise DocumentationError("PlantUML JAR differs from its SHA-256 pin")
    return path


def _validate_doxygen(source_root: pathlib.Path, doxygen: pathlib.Path) -> pathlib.Path:
    """Require the exact Doxygen release used by the documentation gate."""

    doxygen = _exact_existing_file(
        doxygen, "Doxygen", executable=True, allow_symlink=True
    ).resolve(strict=True)
    if (
        _run_small([str(doxygen), "--version"], "Doxygen version", source_root)
        != DOXYGEN_VERSION
    ):
        raise DocumentationError(f"Doxygen must be exactly {DOXYGEN_VERSION}")
    return doxygen


def _public_markdown_sources(source_root: pathlib.Path) -> dict[str, str]:
    """Return canonical-source to staged-path mapping for every public page."""

    docs_root = _exact_existing_directory(source_root / "docs", "public documentation root")
    for forbidden in ("internal", "_plantuml", "_build"):
        candidate = docs_root / forbidden
        if candidate.exists() or candidate.is_symlink():
            raise DocumentationError(f"forbidden directory remains in public docs: {forbidden}")
    pages: dict[str, str] = {}
    for path in sorted(docs_root.rglob("*.md")):
        if path.is_symlink() or not path.is_file():
            raise DocumentationError(f"public document is indirect or nonregular: {path}")
        relative = path.relative_to(source_root).as_posix()
        pages[relative] = path.relative_to(docs_root).as_posix()
    for source, staged in (
        ("CHANGELOG.md", "RELEASE_NOTES.md"),
        ("src/modules/README.md", "BUILTIN_MODULES.md"),
    ):
        _exact_existing_file(source_root / source, "public documentation page")
        pages[source] = staged
    if "docs/diagrams/ordered_cut_boundary_protocol.md" not in pages:
        raise DocumentationError("ordered-CUT protocol guide is absent")
    return pages


def _split_link_target(target: str) -> tuple[str, str]:
    """Split one Markdown link target into path and retained suffix."""

    for separator in ("#", "?"):
        if separator in target:
            path, suffix = target.split(separator, 1)
            return path, separator + suffix
    return target, ""


def _resolve_markdown_target(source: str, target: str) -> str | None:
    """Resolve one relative Markdown target in repository-relative space."""

    path, _suffix = _split_link_target(target)
    if not path or "://" in path or path.startswith(("mailto:", "tel:", "data:", "/")):
        return None
    return posixpath.normpath(posixpath.join(posixpath.dirname(source), path))


def _page_edges(source_root: pathlib.Path, pages: dict[str, str]) -> dict[str, list[str]]:
    """Build the ordered public-document graph from authored Markdown links."""

    edges: dict[str, list[str]] = {}
    for source in pages:
        text = _read_text(source_root / source, "public document")
        outgoing: list[str] = []
        for match in MARKDOWN_LINK_RE.finditer(text):
            target = _resolve_markdown_target(source, match.group("target"))
            if target in pages and target not in outgoing:
                outgoing.append(target)
            elif target is not None and target.endswith(".md") and target not in pages:
                raise DocumentationError(
                    f"public document links an undeclared Markdown page: {source} -> {target}"
                )
        edges[source] = outgoing
    return edges


def _ordered_reachable_pages(edges: dict[str, list[str]]) -> list[str]:
    """Traverse the public page graph in authored breadth-first order."""

    root = "docs/README.md"
    queue: deque[str] = deque([root])
    ordered: list[str] = []
    seen: set[str] = set()
    while queue:
        current = queue.popleft()
        if current in seen:
            continue
        seen.add(current)
        ordered.append(current)
        queue.extend(edges[current])
    missing = sorted(set(edges) - seen)
    if missing:
        raise DocumentationError(
            "public documents are not reachable from docs/README.md: " + ", ".join(missing)
        )
    return ordered


def _rewrite_links(text: str, source: str, pages: dict[str, str]) -> str:
    """Rewrite only mapped public-page links for the generated staging tree."""

    staged_source = pages[source]

    def replace(match: re.Match[str]) -> str:
        """Translate one link only when its target is a staged public page."""

        target_text = match.group("target")
        _target, suffix = _split_link_target(target_text)
        resolved = _resolve_markdown_target(source, target_text)
        if resolved not in pages:
            return match.group(0)
        relative = posixpath.relpath(pages[resolved], posixpath.dirname(staged_source) or ".")
        return match.group("prefix") + relative + suffix + match.group("suffix")

    return MARKDOWN_LINK_RE.sub(replace, text)


def _copy_public_page(
    source_root: pathlib.Path,
    staging_root: pathlib.Path,
    source: str,
    staged: str,
    pages: dict[str, str],
) -> None:
    """Copy one public page while translating only generated-tree links."""

    destination = staging_root / staged
    destination.parent.mkdir(parents=True, exist_ok=True)
    text = _rewrite_links(_read_text(source_root / source, "public document"), source, pages)
    destination.write_text(text, encoding="utf-8", newline="\n")


def _stage_public_sources(
    source_root: pathlib.Path,
    destination: pathlib.Path,
    *,
    java: pathlib.Path,
    plantuml: pathlib.Path,
    dot: pathlib.Path,
) -> None:
    """Populate one complete generated Sphinx source tree."""

    pages = _public_markdown_sources(source_root)
    edges = _page_edges(source_root, pages)
    ordered = _ordered_reachable_pages(edges)
    for source, staged in pages.items():
        _copy_public_page(source_root, destination, source, staged, pages)

    root_path = destination / pages["docs/README.md"]
    root_text = _read_text(root_path, "staged documentation root")
    # The API tree belongs to final composition; an HTML link avoids MyST download copies.
    generated_api = [
        "",
        "## Generated C and C++ API Reference",
        "",
        "The documentation website includes the strict public-header reference at",
        '<a href="api/index.html"><code>api/index.html</code></a>. Private runtime declarations are not',
        "part of that API.",
    ]
    toctree = [
        "",
        "<!-- Generated from the authored public-page graph. -->",
        "```{toctree}",
        ":hidden:",
        ":maxdepth: 4",
        "",
    ]
    toctree.extend(str(pathlib.PurePosixPath(pages[source]).with_suffix("")) for source in ordered[1:])
    toctree.extend(["```", ""])
    root_path.write_text(
        root_text.rstrip() + "\n" + "\n".join(generated_api + toctree),
        encoding="utf-8",
        newline="\n",
    )

    configuration = _exact_existing_file(
        source_root / "docs" / "conf.py", "Sphinx configuration"
    )
    shutil.copyfile(configuration, destination / "conf.py")
    for name in ("_static", "_templates"):
        source_directory = _exact_existing_directory(
            source_root / "docs" / name, f"documentation source {name}"
        )
        target_directory = destination / name
        target_directory.mkdir()
        _copy_regular_tree(source_directory, target_directory)

    build_facts = {
        "java": str(java),
        "plantuml": str(plantuml),
        "dot": str(dot),
        "version": _read_version(source_root),
    }
    (destination / "_kinetum_docs.json").write_text(
        json.dumps(build_facts, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _build_environment() -> dict[str, str]:
    """Return sanitized child state with fixed locale, time, and startup hooks."""

    environment = dict(os.environ)
    for name in tuple(environment):
        upper = name.upper()
        if upper.startswith(
            ("PYTHON", "LD_", "DYLD_", "PIP_", "JAVA_", "JDK_", "PLANTUML_")
        ) or upper in {
            "_JAVA_OPTIONS", "CLASSPATH", "GRAPHVIZ_DOT", "GVBINDIR", "GV_FILE_PATH",
            "GDFONTPATH", "DOTFONTPATH", "SPHINXOPTS",
        }:
            del environment[name]
    environment.update(
        {
            "LC_ALL": "C.UTF-8",
            "LANG": "C.UTF-8",
            "SOURCE_DATE_EPOCH": "0",
            "TZ": "UTC",
            "PIP_CONFIG_FILE": os.devnull,
        }
    )
    return environment


@dataclass(frozen=True)
class _DocumentationTools:
    """Retain the exact interpreter, renderer, and host-tool invocation paths."""

    python: pathlib.Path
    java: pathlib.Path
    plantuml: pathlib.Path
    dot: pathlib.Path


def _discover_tool(name: str, *, retain_alias: bool = False) -> pathlib.Path:
    """Admit a host tool, retaining its alias when argv[0] selects execution mode."""

    selected = shutil.which(name)
    if selected is None:
        raise DocumentationError(f"required documentation prerequisite is missing: {name}")
    admitted = _exact_existing_file(
        pathlib.Path(selected).absolute(), name, executable=True, allow_symlink=True
    )
    return admitted if retain_alias else admitted.resolve(strict=True)


def _file_set_sha256(root: pathlib.Path, paths: Iterable[pathlib.Path]) -> str:
    """Hash sorted relative names and complete bytes without absolute build paths."""

    digest = hashlib.sha256()
    for path in sorted(paths):
        _exact_existing_file(path, "documentation hash input")
        digest.update(path.relative_to(root).as_posix().encode("utf-8") + b"\0")
        with path.open("rb") as stream:
            digest.update(hashlib.file_digest(stream, "sha256").digest())
    return digest.hexdigest()


def _install_plantuml(destination: pathlib.Path) -> pathlib.Path:
    """Download the pinned upstream JAR and admit its digest before use."""

    jar = destination / "plantuml.jar"
    _run_build(
        [
            str(_discover_tool("curl")), "--disable", "--fail", "--location",
            "--proto", "=https", "--proto-redir", "=https",
            "--max-time", "180", "--max-filesize", str(PLANTUML_JAR_LIMIT_BYTES),
            "--output", str(jar),
            f"https://github.com/plantuml/plantuml/releases/download/v{PLANTUML_VERSION}/"
            f"plantuml-{PLANTUML_VERSION}.jar",
        ],
        "pinned PlantUML download", _build_environment(), destination,
    )
    return _validate_plantuml_jar(jar)


def _python_build_requirements(requirements: pathlib.Path) -> str:
    """Select the locked setuptools requirement, retaining every declared hash."""

    selected: list[str] = []
    for line in _read_text(requirements, "Python dependency lock").splitlines():
        if not selected and not line.startswith("setuptools=="):
            continue
        selected.append(line)
        if not line.endswith("\\"):
            break
    if not selected or not any("--hash=sha256:" in line for line in selected):
        raise DocumentationError("Python lock lacks a hash-pinned setuptools build requirement")
    return "\n".join(selected) + "\n"


def _populate_tools(source_root: pathlib.Path, destination: pathlib.Path) -> None:
    """Install locked Python packages and PlantUML at stationary private paths."""

    requirements = _exact_existing_file(
        source_root / "tooling" / "environment" / "requirements.lock", "Python lock"
    )
    environment = _build_environment()
    private_home = destination / "home"
    private_home.mkdir()
    environment["HOME"] = str(private_home)
    environment["XDG_CACHE_HOME"] = str(private_home / ".cache")
    venv_root = destination / "venv"
    _run_build(
        [sys.executable, "-I", "-B", "-m", "venv", str(venv_root)],
        "documentation virtual environment", environment, destination,
    )
    python = venv_root / "bin" / "python3.12"
    install = [
        str(python), "-I", "-B", "-m", "pip", "--isolated", "install",
        "--disable-pip-version-check", "--only-binary=:all:", "--require-hashes",
        "--no-input", "--no-compile",
    ]
    build_requirements = destination / "build-requirements.lock"
    build_requirements.write_text(
        _python_build_requirements(requirements), encoding="ascii", newline="\n"
    )
    _run_build(
        [*install, "--no-deps", "-r", str(build_requirements)],
        "hash-pinned Python build backend", environment, destination,
    )
    _run_build(
        [*install, "--no-build-isolation", "--no-binary=sphinxcontrib-plantuml",
         "-r", str(requirements)],
        "hash-pinned Python tool installation", environment, destination,
    )
    build_requirements.unlink()
    _install_plantuml(destination)


def _prepare_tools(source_root: pathlib.Path, output_root: pathlib.Path) -> _DocumentationTools:
    """Admit native prerequisites and prepare or reuse the private render cache.

    The caller holds the output-directory lock. Changed inputs discard only
    private cache state. Failed admission of a completed cache reports an error.
    """

    if sys.platform != "linux" or platform.machine() not in {"x86_64", "aarch64"}:
        raise DocumentationError("documentation builds require Linux x86_64 or aarch64")
    java, dot = _validate_native_diagram_tools(source_root)
    inputs = _file_set_sha256(source_root, (
        source_root / "tooling" / "environment" / "requirements.lock",
    ))
    identity = hashlib.sha256(
        f"{inputs}\n{sys.executable}\n{sys.version}\n{PLANTUML_VERSION}\n{PLANTUML_SHA256}\n".encode("utf-8")
    ).hexdigest() + "\n"
    destination = DOCUMENTATION_PUBLICATION.generated_path(output_root, "tools")
    stamp = destination / "inputs.sha256"
    if destination.exists() or destination.is_symlink():
        _exact_existing_directory(destination, "documentation tool cache")
        if stamp.exists() or stamp.is_symlink():
            _exact_existing_file(stamp, "documentation tool-cache identity")
        if not stamp.is_file() or stamp.read_text(encoding="ascii") != identity:
            DOCUMENTATION_PUBLICATION.remove_directory(output_root, "tools")
    fresh = not destination.exists()
    if fresh:
        destination.mkdir()
    try:
        if fresh:
            _populate_tools(source_root, destination)
        python = _validate_python_toolchain(source_root, destination / "venv" / "bin" / "python3.12")
        plantuml = _validate_plantuml_jar(destination / "plantuml.jar")
        if fresh:
            stamp.write_text(identity, encoding="ascii", newline="\n")
        return _DocumentationTools(python, java, plantuml, dot)
    except BaseException as error:
        if fresh:
            try:
                DOCUMENTATION_PUBLICATION.remove_directory(output_root, "tools")
            except BaseException as cleanup_error:
                raise DOCUMENTATION_PUBLICATION.DocumentationPublicationDoubleFault(
                    "documentation tool-cache cleanup", error, cleanup_error
                ) from cleanup_error
        raise


def _stage_for_sphinx(
    source_root: pathlib.Path,
    output_root: pathlib.Path,
    source_tree: str,
    tools: _DocumentationTools,
) -> pathlib.Path:
    """Publish one builder-owned source graph through the admitted toolchain."""

    if source_tree not in {HTML_SOURCE_TREE, LINKCHECK_SOURCE_TREE}:
        raise DocumentationError("Sphinx source-tree identity is not declared")

    return DOCUMENTATION_PUBLICATION.replace_directory(
        output_root,
        source_tree,
        lambda destination: _stage_public_sources(
            source_root,
            destination,
            java=tools.java,
            plantuml=tools.plantuml,
            dot=tools.dot,
        ),
    )


def _sphinx_command(
    docs_python: pathlib.Path,
    builder: str,
    source: pathlib.Path,
    output: pathlib.Path,
    doctrees: pathlib.Path,
) -> list[str]:
    """Return the strict shell-free Sphinx command for one builder."""

    return [
        str(docs_python),
        "-I",
        "-B",
        "-m",
        "sphinx.cmd.build",
        "-W",
        "--keep-going",
        "-n",
        "-E",
        "-a",
        "-d",
        str(doctrees),
        "-b",
        builder,
        str(source),
        str(output),
    ]


def _build_html(
    source_root: pathlib.Path, output_root: pathlib.Path, tools: _DocumentationTools
) -> None:
    """Build the strict narrative HTML tree with static PlantUML SVGs."""

    source = _stage_for_sphinx(source_root, output_root, HTML_SOURCE_TREE, tools)
    doctrees = DOCUMENTATION_PUBLICATION.generated_path(output_root, "doctrees")
    DOCUMENTATION_PUBLICATION.remove_directory(output_root, "doctrees")

    def populate(destination: pathlib.Path) -> None:
        """Build one unpublished complete narrative tree."""

        command = _sphinx_command(tools.python, "html", source, destination, doctrees)
        _run_build(command, "Sphinx HTML build", _build_environment(), source)

    DOCUMENTATION_PUBLICATION.replace_directory(output_root, "narrative", populate)


def _build_linkcheck(
    source_root: pathlib.Path, output_root: pathlib.Path, tools: _DocumentationTools
) -> None:
    """Run the explicit networked Sphinx link-check maintenance gate."""

    source = _stage_for_sphinx(source_root, output_root, LINKCHECK_SOURCE_TREE, tools)
    doctrees = DOCUMENTATION_PUBLICATION.generated_path(
        output_root, "linkcheck-doctrees"
    )
    DOCUMENTATION_PUBLICATION.remove_directory(output_root, "linkcheck-doctrees")

    def populate(destination: pathlib.Path) -> None:
        """Build one unpublished complete link-check tree."""

        command = _sphinx_command(
            tools.python, "linkcheck", source, destination, doctrees
        )
        _run_build(command, "Sphinx link check", _build_environment(), source)

    DOCUMENTATION_PUBLICATION.replace_directory(output_root, "linkcheck", populate)


def _admit_public_header_root(
    source_root: pathlib.Path, public_header_root: pathlib.Path
) -> pathlib.Path:
    """Bind Doxygen input to the one installed public-header source root."""

    root = _exact_existing_directory(public_header_root, "public-header root")
    if root != source_root / "include" / "kinetum":
        raise DocumentationError("public-header root differs from installed SDK authority")
    headers = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise DocumentationError(f"public-header source is indirect: {path}")
        if path.is_dir():
            continue
        if not path.is_file() or path.suffix not in {".h", ".hpp"}:
            raise DocumentationError(f"public-header root contains an unowned member: {path}")
        headers += 1
    if headers == 0:
        raise DocumentationError("public-header root contains no headers")
    return root


def _render_doxyfile(
    source_root: pathlib.Path, public_header_root: pathlib.Path, output: pathlib.Path
) -> str:
    """Render the strict Doxygen template from exact repository paths."""

    public_header_root = _admit_public_header_root(source_root, public_header_root)
    template_path = _exact_existing_file(
        source_root / "docs" / "Doxyfile.in", "Doxygen template"
    )
    template = _read_text(template_path, "Doxygen template")
    replacements = {
        "@KINETUM_VERSION@": _read_version(source_root),
        "@KINETUM_DOXYGEN_OUTPUT@": str(output),
        "@KINETUM_SOURCE_ROOT@": str(source_root),
        "@KINETUM_PUBLIC_HEADER_ROOT@": str(public_header_root),
        "@KINETUM_INCLUDE_ROOT@": str(source_root / "include"),
    }
    for key, value in replacements.items():
        template = template.replace(key, value)
    if "@KINETUM_" in template:
        raise DocumentationError("Doxygen template retains an unresolved token")
    return template


def _build_api(source_root: pathlib.Path, output_root: pathlib.Path, doxygen: pathlib.Path) -> None:
    """Build strict public-header Doxygen HTML from the installed-header root."""

    public_header_root = _admit_public_header_root(
        source_root, source_root / "include" / "kinetum"
    )

    def populate(destination: pathlib.Path) -> None:
        """Build one unpublished complete Doxygen API tree."""

        config = destination / "Doxyfile"
        config.write_text(
            _render_doxyfile(source_root, public_header_root, destination),
            encoding="utf-8",
            newline="\n",
        )
        _run_build(
            [str(doxygen), str(config)],
            "Doxygen API build",
            _build_environment(),
            source_root,
        )
        if not (destination / "html" / "index.html").is_file():
            raise DocumentationError("Doxygen did not produce the public API index")

    DOCUMENTATION_PUBLICATION.replace_directory(output_root, "doxygen", populate)


def _copy_regular_tree(source: pathlib.Path, destination: pathlib.Path) -> None:
    """Copy one generated tree while rejecting links and special files."""

    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        target = destination / relative
        if path.is_symlink():
            raise DocumentationError(f"generated documentation contains a symlink: {relative}")
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if not path.is_file():
            raise DocumentationError(f"generated documentation contains a special file: {relative}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)


def _compose_site(source_root: pathlib.Path, output_root: pathlib.Path, destination: pathlib.Path) -> None:
    """Compose narrative, API, and redistributed-license trees exactly once."""

    narrative = _exact_existing_directory(output_root / "narrative", "narrative HTML")
    api = _exact_existing_directory(output_root / "doxygen" / "html", "Doxygen HTML")
    licenses = _exact_existing_directory(
        source_root / "third_party" / "documentation" / "licenses",
        "documentation asset-license root",
    )
    _copy_regular_tree(narrative, destination)
    api_destination = destination / "api"
    api_destination.mkdir()
    _copy_regular_tree(api, api_destination)
    license_destination = destination / "_licenses"
    license_destination.mkdir()
    _copy_regular_tree(licenses, license_destination)
    shutil.copyfile(source_root / "LICENSE", license_destination / "APACHE-2.0.txt")


def _iter_regular_files(root: pathlib.Path) -> Iterable[pathlib.Path]:
    """Yield one generated tree's regular files after rejecting other types."""

    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise DocumentationError(f"documentation output contains a symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise DocumentationError(f"documentation output contains a special file: {path}")
        yield path


def _html_asset_references(text: str, properties: dict[str, list[str]]) -> tuple[list[str], bool, int]:
    """Return page-time references, base-element presence, and rendered diagram count."""

    parser = _AssetReferenceParser()
    parser.feed(text)
    parser.close()
    definitions = dict(properties)
    for name, values in _collect_css_properties(parser.styles).items():
        definitions[name] = [*properties.get(name, []), *values]
    for style in parser.styles:
        parser.references.extend(_css_references(style, definitions))
    return parser.references, parser.has_base, parser.plantuml_images


def _css_asset_references(text: str, properties: dict[str, list[str]]) -> list[str]:
    """Return every URL-bearing reference in one generated stylesheet."""

    return _css_references(text, properties)


def _xml_asset_references(text: str, properties: dict[str, list[str]]) -> list[str]:
    """Return every URL-bearing reference in one generated SVG/XML asset."""

    references = [match.group("url").strip() for match in XML_ASSET_RE.finditer(text)]
    styled_references, _, _ = _html_asset_references(text, properties)
    references.extend(styled_references)
    return references


def _site_css_properties(site: pathlib.Path) -> dict[str, list[str]]:
    """Collect generated stylesheet and inline declarations before reference checks."""

    texts = []
    for path in _iter_regular_files(site):
        if path.suffix.lower() == ".css":
            texts.append(_read_text(path, "generated stylesheet"))
        elif path.suffix.lower() in {".html", ".svg", ".xml"}:
            parser = _AssetReferenceParser()
            parser.feed(_read_text(path, "generated markup"))
            parser.close()
            texts.extend(parser.styles)
    return _collect_css_properties(texts)


def _local_asset_target(source: str, value: str) -> str | None:
    """Resolve one self-contained or site-local asset reference exactly.

    Args:
        source: Canonical site-relative path containing the reference.
        value: Authored or generated reference text.

    Returns:
        Canonical site-relative target, or ``None`` for an inline data value or
        same-document reference.

    Raises:
        DocumentationError: The reference is external, malformed, absolute, or
            escapes the generated site.
    """

    reference = html.unescape(value).strip()
    if not reference:
        raise DocumentationError(f"generated asset reference is empty: {source}")
    try:
        parsed = urllib.parse.urlsplit(reference)
    except ValueError as error:
        raise DocumentationError(f"generated asset reference is malformed: {source}") from error
    if parsed.scheme.lower() == "data":
        return None
    if parsed.scheme or parsed.netloc or reference.startswith("//"):
        raise DocumentationError(f"generated asset reference is external: {source}: {reference[:512]!r}")
    if re.search(r"%(?![0-9A-Fa-f]{2})", parsed.path):
        raise DocumentationError(f"generated asset reference has malformed encoding: {source}")
    try:
        decoded_path = urllib.parse.unquote_to_bytes(parsed.path).decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise DocumentationError(f"generated asset reference is not UTF-8: {source}") from error
    if "\x00" in decoded_path or "\\" in decoded_path:
        raise DocumentationError(f"generated asset reference contains a forbidden path byte: {source}")
    if not decoded_path:
        if parsed.query or parsed.fragment or reference == "#":
            return None
        raise DocumentationError(f"generated asset reference has no target: {source}")
    if decoded_path.startswith("/"):
        raise DocumentationError(f"generated asset reference is root-relative: {source}")
    target = posixpath.normpath(posixpath.join(posixpath.dirname(source), decoded_path))
    if target == ".." or target.startswith("../") or target.startswith("/"):
        raise DocumentationError(f"generated asset reference escapes the site: {source}")
    return target


def _verify_asset_references(
    source: str, text: str, members: set[str], properties: dict[str, list[str]],
) -> int:
    """Validate page-time asset membership and return the rendered diagram count."""

    suffix = pathlib.PurePosixPath(source).suffix.lower()
    has_base = False
    diagrams = 0
    if suffix == ".html":
        references, has_base, diagrams = _html_asset_references(text, properties)
    elif suffix == ".css":
        references = _css_asset_references(text, properties)
    elif suffix in {".svg", ".xml"}:
        references = _xml_asset_references(text, properties)
    else:
        return 0
    if has_base:
        raise DocumentationError(f"generated HTML contains a base element: {source}")
    for reference in references:
        target = _local_asset_target(source, reference)
        if target is not None and target not in members:
            raise DocumentationError(
                f"generated asset reference names a missing site member: {source} -> {target}"
            )
    return diagrams


def _verify_license_projection(source_root: pathlib.Path, site: pathlib.Path) -> None:
    """Require exact documentation-license membership and bytes in the site."""

    source = _exact_existing_directory(
        source_root / "third_party" / "documentation" / "licenses",
        "documentation asset-license root",
    )
    destination = _exact_existing_directory(site / "_licenses", "site license root")
    expected = {
        path.relative_to(source).as_posix(): path
        for path in _iter_regular_files(source)
    }
    expected["APACHE-2.0.txt"] = _exact_existing_file(
        source_root / "LICENSE", "Kinetum license"
    )
    observed = {
        path.relative_to(destination).as_posix(): path
        for path in _iter_regular_files(destination)
    }
    if set(observed) != set(expected):
        raise DocumentationError("documentation license membership differs from its source authority")
    for relative, source_path in expected.items():
        if observed[relative].read_bytes() != source_path.read_bytes():
            raise DocumentationError(f"documentation license bytes differ: {relative}")


def _count_plantuml_fences(source_root: pathlib.Path) -> int:
    """Count authored PlantUML directives in the complete public page set."""

    return sum(
        len(re.findall(r"^```\{uml\}[ \t]*$", _read_text(source_root / source, "public document"), re.MULTILINE))
        for source in _public_markdown_sources(source_root)
    )


def _verify_site_tree(
    source_root: pathlib.Path, output_root: pathlib.Path, site: pathlib.Path
) -> None:
    """Verify one unpublished or published offline site tree completely."""

    source_root = _exact_existing_directory(source_root, "source root")
    output_root = _exact_existing_directory(output_root, "documentation output root")
    site = _exact_existing_directory(site, "composed documentation site")
    required = (
        "index.html",
        "README.html",
        "searchindex.js",
        "api/index.html",
        "_licenses/README.md",
    )
    for relative in required:
        if not (site / relative).is_file():
            raise DocumentationError(f"documentation site is missing {relative}")

    for staged in _public_markdown_sources(source_root).values():
        relative = str(pathlib.PurePosixPath(staged).with_suffix(".html"))
        if not (site / relative).is_file():
            raise DocumentationError(f"documentation site omitted public page {relative}")

    site_members = {
        path.relative_to(site).as_posix() for path in _iter_regular_files(site)
    }
    source_only = sorted(
        (site_members & DOCUMENTATION_SOURCE_ONLY_MEMBERS)
        | {name for name in site_members if "_plantuml" in pathlib.PurePosixPath(name).parts}
    )
    if source_only:
        raise DocumentationError(
            "documentation site contains source-only members: "
            + ", ".join(source_only)
        )

    _verify_license_projection(source_root, site)
    css_properties = _site_css_properties(site)

    forbidden_bytes = (
        str(source_root).encode(),
        str(output_root.resolve(strict=False)).encode(),
        b"/private/tmp/",
    )
    rendered_diagrams = 0
    for path in _iter_regular_files(site):
        relative = path.relative_to(site).as_posix()
        data = path.read_bytes()
        if any(value in data for value in forbidden_bytes):
            raise DocumentationError(f"generated output leaks a forbidden path: {path}")
        if path.suffix.lower() not in {".html", ".css", ".js", ".svg", ".xml"}:
            continue
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeError as error:
            raise DocumentationError(f"generated text asset is not UTF-8: {path}") from error
        rendered_diagrams += _verify_asset_references(relative, text, site_members, css_properties)

    expected_diagrams = _count_plantuml_fences(source_root)
    if rendered_diagrams != expected_diagrams:
        raise DocumentationError(
            f"rendered PlantUML membership differs: expected {expected_diagrams}, got {rendered_diagrams}"
        )


def verify_site(source_root: pathlib.Path, output_root: pathlib.Path) -> None:
    """Verify the complete product and its correspondence to current source inputs."""

    output_root = _exact_existing_directory(output_root, "documentation output root")
    _verify_site_tree(source_root, output_root, output_root / "html")
    _verify_build_manifest(source_root, output_root / "html")


def _source_sha256(source_root: pathlib.Path) -> str:
    """Derive staleness identity from all rendered inputs and their producer code."""

    paths = [source_root / name for name in (
        "VERSION", "LICENSE", "CHANGELOG.md", "src/modules/README.md",
        "tooling/release/documentation/build_documentation.py",
        "tooling/release/documentation/documentation_process.py",
        "tooling/release/documentation/documentation_publication.py",
        "tooling/environment/requirements.lock",
    )]
    for name in ("docs", "include/kinetum", "third_party/documentation/licenses"):
        root = _exact_existing_directory(source_root / name, "documentation source input")
        paths.extend(_iter_regular_files(root))
    return _file_set_sha256(source_root, paths)


def _site_sha256(site: pathlib.Path) -> str:
    """Hash every completed payload member except the receipt that records this hash."""

    return _file_set_sha256(site, (
        path for path in _iter_regular_files(site) if path != site / BUILD_MANIFEST
    ))


def _verify_build_manifest(source_root: pathlib.Path, site: pathlib.Path) -> None:
    """Reject a stale or modified website before hosting its completed bytes."""

    manifest_path = _exact_existing_file(site / BUILD_MANIFEST, "documentation build manifest")
    manifest = _parse_json_object(_read_text(manifest_path, "documentation build manifest"),
                                  "documentation build manifest")
    if set(manifest) != {"source_sha256", "payload_sha256"} or any(
        not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in manifest.values()
    ):
        raise DocumentationError("documentation build manifest must contain two exact SHA-256 values")
    if manifest["source_sha256"] != _source_sha256(source_root):
        raise DocumentationError("documentation is stale; rebuild it from the current source")
    if manifest["payload_sha256"] != _site_sha256(site):
        raise DocumentationError("documentation payload differs from its completed build")


def _compose(source_root: pathlib.Path, output_root: pathlib.Path, source_hash: str) -> None:
    """Publish one verified site only if its source remained unchanged during rendering."""

    def populate(destination: pathlib.Path) -> None:
        """Compose and verify one complete unpublished site."""

        _compose_site(source_root, output_root, destination)
        _verify_site_tree(source_root, output_root, destination)
        if _source_sha256(source_root) != source_hash:
            raise DocumentationError("documentation inputs changed during the build")
        (destination / BUILD_MANIFEST).write_text(
            json.dumps({"source_sha256": source_hash, "payload_sha256": _site_sha256(destination)},
                       sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii", newline="\n",
        )

    def verify_published(published: pathlib.Path) -> None:
        """Revalidate the published identity while replacement remains reversible."""

        _verify_site_tree(source_root, output_root, published)
        _verify_build_manifest(source_root, published)

    DOCUMENTATION_PUBLICATION.replace_directory(
        output_root,
        "html",
        populate,
        verify_published,
    )


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    """Expose the completed product and maintenance actions, never internal phases."""

    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-root", type=pathlib.Path,
                        help="absolute build directory (default: source-root/build/docs)")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--verify-only", action="store_true",
                         help="verify the completed site against current source without building")
    actions.add_argument("--check-links", action="store_true",
                         help="run the networked external-link check")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Own setup, rendering, verification, and final publication in one invocation."""

    try:
        args = _parse_args(sys.argv[1:] if argv is None else argv)
        _require_running_python()
        source_root = _exact_existing_directory(pathlib.Path(__file__).resolve().parents[3], "source root")
        if args.output_root is None:
            parent = source_root / "build"
            if not args.verify_only:
                parent.mkdir(exist_ok=True)
            args.output_root = parent / "docs"
        output_root = _admit_output_root(args.output_root, create=not args.verify_only)
        descriptor = os.open(output_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            mode = fcntl.LOCK_SH if args.verify_only else fcntl.LOCK_EX
            try:
                fcntl.flock(descriptor, mode | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise DocumentationError("documentation output is in use by another invocation") from error
            if args.verify_only:
                verify_site(source_root, output_root)
            elif args.check_links:
                _build_linkcheck(source_root, output_root, _prepare_tools(source_root, output_root))
            else:
                source_hash = _source_sha256(source_root)
                doxygen = _validate_doxygen(source_root, _discover_tool("doxygen"))
                tools = _prepare_tools(source_root, output_root)
                _build_api(source_root, output_root, doxygen)
                _build_html(source_root, output_root, tools)
                _compose(source_root, output_root, source_hash)
        finally:
            os.close(descriptor)
    except (
        DocumentationError,
        DOCUMENTATION_PUBLICATION.DocumentationPublicationError,
        OSError,
        ValueError,
    ) as error:
        print(f"build_documentation.py: error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
