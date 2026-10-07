#!/usr/bin/env python3
"""Build and install the exact Kinetum DPDK dependency package.

The producer consumes one source-controlled policy, verifies every downloaded
byte, builds only the declared static-PIC archive closure, and publishes one
relocatable CMake CONFIG package. It never reads distro DPDK metadata or turns
linker spellings into archive paths.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any
import urllib.request


DPDK_SOURCE_PATCH = "third_party/dpdk/i40e_close.patch"
POLICY_FILES = (
    "third_party/dpdk/dependency_manifest.json",
    DPDK_SOURCE_PATCH,
    "third_party/dpdk/KinetumDPDKConfig.cmake.in",
    "third_party/dpdk/KinetumDPDKConfigVersion.cmake.in",
    "tooling/environment/build_kinetum_dpdk.py",
)
PACKAGE_CONFIG_DIRECTORY = Path("lib/cmake/KinetumDPDK")
PACKAGE_DIRECTORY_MODE = 0o755
PACKAGE_FILE_MODE = 0o644
PACKAGE_MANIFEST = Path("share/kinetum/dpdk/build_manifest.json")
STATIC_CLOSURE_NOTICE = Path(
    "share/licenses/KinetumDPDK/DPDK_STATIC_CLOSURE_NOTICE.txt"
)
PACKAGE_MANIFEST_KEYS = frozenset({
    "archives",
    "builder",
    "dependency_sha256",
    "dependency_version",
    "dynamic_link_libraries",
    "files",
    "meson_options",
    "meson_sha256",
    "meson_version",
    "payload_sha256",
    "pmd_info_symbols",
    "policy_sha256",
    "reproducibility",
    "schema_version",
    "tuple",
    "tuple_configuration",
})
PRODUCER_PATH = "/usr/bin:/bin"
BUILD_JSON_LIMIT_BYTES = 16 * 1024 * 1024
BUILD_METADATA_LIMIT_BYTES = 16 * 1024 * 1024
ATTRIBUTION_SOURCE_LIMIT_BYTES = 8 * 1024 * 1024
DEPENDENCY_DOWNLOAD_LIMIT_BYTES = 64 * 1024 * 1024
DEPENDENCY_DOWNLOAD_CHUNK_BYTES = 1024 * 1024
DEPENDENCY_DOWNLOAD_SOCKET_TIMEOUT_SECONDS = 60
AT_FDCWD = -100
RENAME_NOREPLACE = 1
FAILURE_TEXT_LIMIT = 2048


class ProducerError(RuntimeError):
    """Report one deterministic producer-contract failure."""


class ProducerDoubleFault(ProducerError):
    """Retain one producer failure and its independent cleanup failure."""

    def __init__(
        self,
        operation: str,
        originating_error: BaseException,
        cleanup_error: BaseException,
    ) -> None:
        """Construct one bounded diagnostic while retaining both causes."""

        self.originating_error = originating_error
        self.cleanup_error = cleanup_error
        super().__init__(
            f"{operation}; originating failure: "
            f"{_failure_text(originating_error)}; cleanup failure: "
            f"{_failure_text(cleanup_error)}"
        )


def _failure_text(error: BaseException) -> str:
    """Return one bounded escaped exception identity."""

    text = f"{type(error).__name__}: {str(error)!r}"
    if len(text) <= FAILURE_TEXT_LIMIT:
        return text
    return text[: FAILURE_TEXT_LIMIT - 3] + "..."


def _reject_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build one object while rejecting duplicate member names."""

    keys = [key for key, _value in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate JSON member")
    return dict(pairs)


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

    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            current.encode("utf-8", errors="strict")
        elif isinstance(current, list):
            pending.extend(current)
        elif isinstance(current, dict):
            for key, item in current.items():
                key.encode("utf-8", errors="strict")
                pending.append(item)


def _parse_json_document(raw: bytes, role: str) -> Any:
    """Parse one bounded unambiguous JSON byte document."""

    try:
        if not isinstance(raw, bytes):
            raise TypeError("JSON input is not bytes")
        if not raw or len(raw) > BUILD_JSON_LIMIT_BYTES:
            raise ValueError("empty or oversized JSON")
        text = raw.decode("utf-8", errors="strict")
        result = json.loads(
            text,
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
        raise ProducerError(f"{role} is not exact JSON") from error
    return result


def _parse_json_object(raw: bytes, role: str) -> dict[str, Any]:
    """Parse one bounded unambiguous JSON byte document with an object root."""

    result = _parse_json_document(raw, role)
    if not isinstance(result, dict):
        raise ProducerError(f"{role} does not have an object root")
    return result


def _parse_json_array(raw: bytes, role: str) -> list[Any]:
    """Parse one bounded unambiguous JSON byte document with an array root."""

    result = _parse_json_document(raw, role)
    if not isinstance(result, list):
        raise ProducerError(f"{role} does not have an array root")
    return result


def sha256_file(path: Path) -> str:
    """Return the SHA-256 identity of one regular file."""

    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repository_root() -> Path:
    """Return the source root owning this producer."""

    return Path(__file__).resolve().parents[2]


def load_policy(root: Path) -> tuple[dict[str, Any], str]:
    """Load the exact dependency policy and derive its complete identity."""

    policy_paths = [root / relative for relative in POLICY_FILES]
    for path in policy_paths:
        if not path.is_file():
            raise ProducerError(f"dependency policy input is missing: {path}")

    manifest_path = root / POLICY_FILES[0]
    try:
        policy_bytes = manifest_path.read_bytes()
    except OSError as error:
        raise ProducerError("dependency policy is unavailable") from error
    policy = _parse_json_object(
        policy_bytes,
        "dependency policy",
    )
    schema_version = policy.get("schema_version")
    if not isinstance(schema_version, int) or isinstance(schema_version, bool) or schema_version != 1:
        raise ProducerError("unsupported dependency policy schema_version")

    identity_material = "".join(
        f"{path.relative_to(root).as_posix()}:{sha256_file(path)}\n"
        for path in policy_paths
    )
    return policy, hashlib.sha256(identity_material.encode("ascii")).hexdigest()


def default_package_prefix(
    version: str, tuple_name: str, policy_sha256: str,
) -> Path:
    """Return the immutable package root for one exact producer policy."""

    return (
        Path("/opt/kinetum/dependencies/dpdk")
        / version
        / tuple_name
        / policy_sha256
    )


def command_output(arguments: list[str]) -> str:
    """Probe a tool under the build's command path and locale."""

    result = subprocess.run(
        arguments,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={"PATH": PRODUCER_PATH, "LC_ALL": "C.UTF-8"},
    )
    return result.stdout.strip()


def parse_os_release() -> dict[str, str]:
    """Read the exact Linux release identity without invoking a shell."""

    values: dict[str, str] = {}
    with Path("/etc/os-release").open("r", encoding="utf-8") as source:
        for raw_line in source:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    return values


def select_tuple(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Select the one declared build tuple matching this host."""

    if platform.system() != "Linux":
        raise ProducerError("KinetumDPDK can be produced only on Linux")
    machine = platform.machine()
    matches = [
        (name, row)
        for name, row in policy["tuples"].items()
        if row["machine"] == machine
    ]
    if len(matches) != 1:
        raise ProducerError(f"unsupported or ambiguous build machine: {machine}")
    return matches[0]


def validate_builder(policy: dict[str, Any]) -> None:
    """Fail unless the source-controlled builder identity is exact."""

    expected = policy["builder"]
    os_release = parse_os_release()
    actual = {
        "os_id": os_release.get("ID", ""),
        "os_version": os_release.get("VERSION_ID", ""),
        "cc_version": command_output(["cc", "-dumpfullversion", "-dumpversion"]),
        "ld_version": command_output(["ld", "--version"]).splitlines()[0],
        "ar_version": command_output(["ar", "--version"]).splitlines()[0],
        "as_version": command_output(["as", "--version"]).splitlines()[0],
        "ninja_version": command_output(["ninja", "--version"]),
        "pkg_config_version": command_output(["pkg-config", "--version"]),
        "python_version": platform.python_version(),
        "pyelftools_version": command_output([
            sys.executable, "-I", "-B", "-c",
            "import elftools; print(elftools.__version__)",
        ]),
    }
    for key, expected_value in expected.items():
        if key == "source_date_epoch":
            continue
        if actual.get(key) != expected_value:
            raise ProducerError(
                f"builder {key} mismatch: expected {expected_value!r}, "
                f"found {actual.get(key)!r}"
            )
    for executable in ("ar", "as", "cc", "ld", "nm", "ninja", "patch", "pkg-config"):
        if shutil.which(executable, path=PRODUCER_PATH) is None:
            raise ProducerError(f"required producer tool is missing: {executable}")


def apply_package_umask(policy: dict[str, Any]) -> None:
    """Apply the exact package-creation mask declared by producer policy."""

    spelling = policy["reproducibility"].get("package_umask")
    if (
        not isinstance(spelling, str)
        or len(spelling) != 4
        or spelling[0] != "0"
        or any(character not in "01234567" for character in spelling)
    ):
        raise ProducerError("dependency policy has an invalid package_umask")
    mask = int(spelling, 8)
    if (
        (0o777 & ~mask) != PACKAGE_DIRECTORY_MODE
        or (0o666 & ~mask) != PACKAGE_FILE_MODE
    ):
        raise ProducerError(
            "dependency policy package_umask does not produce the exact "
            "reader-safe package modes"
        )
    os.umask(mask)


def build_environment(
    policy: dict[str, Any], temporary_root: Path,
) -> dict[str, str]:
    """Construct the complete closed environment for native build commands."""

    home = temporary_root / "home"
    temporary_directory = temporary_root / "tmp"
    pkg_config_directory = temporary_root / "pkgconfig"
    home.mkdir()
    temporary_directory.mkdir()
    pkg_config_directory.mkdir()
    return {
        "HOME": os.fspath(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": PRODUCER_PATH,
        "PKG_CONFIG_LIBDIR": os.fspath(pkg_config_directory),
        "PKG_CONFIG_PATH": "",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "SOURCE_DATE_EPOCH": str(policy["builder"]["source_date_epoch"]),
        "TMPDIR": os.fspath(temporary_directory),
        "TZ": "UTC",
        "ZERO_AR_DATE": "1",
    }


def _prepare_exact_directory(path: Path, role: str) -> Path:
    """Create or admit one absolute direct producer-owned directory."""

    if not path.is_absolute() or ".." in path.parts or path.absolute() != path:
        raise ProducerError(f"{role} must be one normalized absolute path")
    try:
        prospective = path.resolve(strict=False)
    except OSError as error:
        raise ProducerError(f"{role} is unavailable: {path}") from error
    if prospective != path:
        raise ProducerError(f"{role} must be one direct directory: {path}")
    try:
        path.mkdir(mode=PACKAGE_DIRECTORY_MODE, parents=True, exist_ok=True)
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as error:
        raise ProducerError(f"{role} is unavailable: {path}") from error
    if resolved != path or not stat.S_ISDIR(metadata.st_mode):
        raise ProducerError(f"{role} must be one direct directory: {path}")
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ProducerError(f"{role} has an untrusted owner or writable mode")
    return path


def _require_renameat2() -> Any:
    """Return libc renameat2 or fail before producer side effects."""

    if sys.platform != "linux":
        raise ProducerError("atomic dependency publication requires Linux renameat2")
    process_image = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = process_image.renameat2
    except AttributeError as error:
        raise ProducerError(
            "atomic dependency publication requires libc renameat2"
        ) from error
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    return renameat2


def _rename_no_replace(source: Path, target: Path) -> None:
    """Atomically publish one sibling file or directory only if target is absent."""

    if (
        not source.is_absolute()
        or not target.is_absolute()
        or source.parent != target.parent
        or source.is_symlink()
    ):
        raise ProducerError("dependency publication identities are not exact siblings")
    try:
        source_metadata = source.lstat()
    except OSError as error:
        raise ProducerError("dependency publication candidate is unavailable") from error
    if not (stat.S_ISREG(source_metadata.st_mode) or stat.S_ISDIR(source_metadata.st_mode)):
        raise ProducerError("dependency publication candidate has an invalid type")
    renameat2 = _require_renameat2()
    ctypes.set_errno(0)
    result = renameat2(
        AT_FDCWD,
        os.fsencode(source),
        AT_FDCWD,
        os.fsencode(target),
        RENAME_NOREPLACE,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        error_type = FileExistsError if error_number == errno.EEXIST else OSError
        raise error_type(
            error_number,
            os.strerror(error_number),
            f"{source} -> {target}",
        )


def _cache_entry_is_exact(path: Path, expected_sha256: str) -> bool | None:
    """Return true/false for an existing cache entry or None for exact absence."""

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or metadata.st_size <= 0
        or metadata.st_size > DEPENDENCY_DOWNLOAD_LIMIT_BYTES
    ):
        return False
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    with os.fdopen(descriptor, "rb") as source:
        opened = os.fstat(source.fileno())
        if (opened.st_dev, opened.st_ino) != (
            metadata.st_dev,
            metadata.st_ino,
        ):
            return False
        if (
            opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) & 0o022
            or opened.st_size <= 0
            or opened.st_size > DEPENDENCY_DOWNLOAD_LIMIT_BYTES
        ):
            return False
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = source.read(
                min(
                    DEPENDENCY_DOWNLOAD_CHUNK_BYTES,
                    DEPENDENCY_DOWNLOAD_LIMIT_BYTES - size + 1,
                )
            )
            if not chunk:
                break
            size += len(chunk)
            if size > DEPENDENCY_DOWNLOAD_LIMIT_BYTES:
                return False
            digest.update(chunk)
        final = os.fstat(source.fileno())
    opened_identity = (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
        opened.st_mtime_ns,
        opened.st_ctime_ns,
    )
    final_identity = (
        final.st_dev,
        final.st_ino,
        final.st_size,
        final.st_mtime_ns,
        final.st_ctime_ns,
    )
    return (
        size == opened.st_size
        and final_identity == opened_identity
        and digest.hexdigest() == expected_sha256
    )


def _cleanup_file_after_error(path: Path, originating_error: BaseException) -> None:
    """Remove one private download candidate without masking its first failure."""

    try:
        path.unlink()
    except BaseException as cleanup_error:
        raise ProducerDoubleFault(
            "failed to remove dependency download candidate",
            originating_error,
            cleanup_error,
        ) from cleanup_error


def _cleanup_directory_after_error(
    path: Path,
    originating_error: BaseException,
) -> None:
    """Remove one private package candidate without masking its first failure."""

    try:
        shutil.rmtree(path)
    except BaseException as cleanup_error:
        raise ProducerDoubleFault(
            "failed to remove dependency package candidate",
            originating_error,
            cleanup_error,
        ) from cleanup_error


def download_verified(url: str, expected_sha256: str, cache_path: Path) -> Path:
    """Return one cached download only after exact content verification."""

    _prepare_exact_directory(cache_path.parent, "dependency cache directory")
    existing = _cache_entry_is_exact(cache_path, expected_sha256)
    if existing is not None:
        if not existing:
            raise ProducerError(
                f"cached dependency has the wrong identity: {cache_path}"
            )
        return cache_path

    descriptor, candidate_name = tempfile.mkstemp(
        prefix=f".{cache_path.name}.candidate-",
        dir=cache_path.parent,
    )
    candidate = Path(candidate_name)
    try:
        output = os.fdopen(descriptor, "wb", closefd=True)
    except BaseException as error:
        try:
            os.close(descriptor)
        except BaseException as cleanup_error:
            raise ProducerDoubleFault(
                "failed to adopt dependency download descriptor",
                error,
                cleanup_error,
            ) from cleanup_error
        _cleanup_file_after_error(candidate, error)
        raise
    consumed = False
    try:
        digest = hashlib.sha256()
        size = 0
        with output:
            with urllib.request.urlopen(
                url,
                timeout=DEPENDENCY_DOWNLOAD_SOCKET_TIMEOUT_SECONDS,
            ) as response:
                while True:
                    chunk = response.read(
                        min(
                            DEPENDENCY_DOWNLOAD_CHUNK_BYTES,
                            DEPENDENCY_DOWNLOAD_LIMIT_BYTES - size + 1,
                        )
                    )
                    if not chunk:
                        break
                    if not isinstance(chunk, bytes):
                        raise ProducerError("dependency download returned non-byte data")
                    size += len(chunk)
                    if size > DEPENDENCY_DOWNLOAD_LIMIT_BYTES:
                        raise ProducerError("dependency download exceeds its byte bound")
                    if output.write(chunk) != len(chunk):
                        raise ProducerError("dependency download write was incomplete")
                    digest.update(chunk)
            if size == 0 or digest.hexdigest() != expected_sha256:
                raise ProducerError(
                    f"downloaded dependency has the wrong identity: {url}"
                )
            output.flush()
            os.fchmod(output.fileno(), PACKAGE_FILE_MODE)
            os.fsync(output.fileno())

        try:
            _rename_no_replace(candidate, cache_path)
        except FileExistsError:
            if _cache_entry_is_exact(cache_path, expected_sha256) is not True:
                raise ProducerError(
                    f"dependency cache race published a foreign object: {cache_path}"
                ) from None
        else:
            consumed = True
    except BaseException as error:
        if not consumed:
            _cleanup_file_after_error(candidate, error)
        raise

    if not consumed:
        try:
            candidate.unlink()
        except OSError as error:
            raise ProducerError(
                "failed to remove redundant dependency download candidate"
            ) from error
    return cache_path


def normalize_archive_path(path: PurePosixPath) -> PurePosixPath | None:
    """Lexically normalize one relative archive path or report root escape."""

    normalized: list[str] = []
    for part in path.parts:
        if part == "..":
            if not normalized:
                return None
            normalized.pop()
        elif part != ".":
            normalized.append(part)
    return PurePosixPath(*normalized)


def path_is_within_archive_root(
    path: PurePosixPath, archive_root: PurePosixPath,
) -> bool:
    """Return whether one normalized path is beneath the exact archive root."""

    return path.parts[:len(archive_root.parts)] == archive_root.parts


def validate_tar_member(
    member: tarfile.TarInfo, archive_root: PurePosixPath,
) -> None:
    """Reject archive members that could escape or create special files."""

    path = PurePosixPath(member.name)
    if path.is_absolute() or ".." in path.parts:
        raise ProducerError(f"dependency archive contains an unsafe path: {member.name}")
    if not path_is_within_archive_root(path, archive_root):
        raise ProducerError(
            "dependency archive contains content outside its exact root: "
            f"{member.name}"
        )
    if member.ischr() or member.isblk() or member.isfifo():
        raise ProducerError(f"dependency archive contains a special file: {member.name}")
    if member.issym() or member.islnk():
        if not member.linkname:
            raise ProducerError(
                f"dependency archive contains an empty link: {member.name}"
            )
        target = PurePosixPath(member.linkname)
        unresolved = path.parent.joinpath(target) if member.issym() else target
        resolved = normalize_archive_path(unresolved)
        if (
            target.is_absolute()
            or resolved is None
            or not path_is_within_archive_root(resolved, archive_root)
        ):
            raise ProducerError(
                f"dependency archive contains an escaping link: {member.name}"
            )


def extract_verified(archive: Path, destination: Path, expected_root: str) -> Path:
    """Extract one verified archive beneath a temporary owner directory."""

    archive_root = PurePosixPath(expected_root)
    if (
        archive_root.is_absolute()
        or not archive_root.parts
        or ".." in archive_root.parts
    ):
        raise ProducerError("dependency policy has an invalid archive root")
    with tarfile.open(archive, "r:*") as source:
        members = source.getmembers()
        for member in members:
            validate_tar_member(member, archive_root)
        # The verified source archive retains its upstream modes and links;
        # complete member admission above owns the extraction boundary.
        source.extractall(destination, members=members, filter="fully_trusted")
    root = destination / expected_root
    if not root.is_dir():
        raise ProducerError(f"dependency archive lacks exact root {expected_root!r}")
    return root


def write_meson_native_file(path: Path) -> None:
    """Bind both Meson Python lookups to this producer's interpreter.

    Reject a path that Meson's machine-file string grammar could reinterpret;
    there is no shell expansion or alternate interpreter discovery.
    """

    python = sys.executable
    if (
        not Path(python).is_absolute()
        or any(character in python for character in "'\\\r\n\x00")
        or "@DIRNAME@" in python
        or "@GLOBAL_SOURCE_ROOT@" in python
    ):
        raise ProducerError("producer interpreter cannot be represented in a Meson native file")
    path.write_text(
        f"[binaries]\npython = '{python}'\npython3 = python\n",
        encoding="utf-8",
    )


def meson_arguments(
    policy: dict[str, Any], tuple_row: dict[str, Any], meson: Path,
    source: Path, build: Path, native_file: Path,
) -> list[str]:
    """Render the complete declared Meson setup command."""

    options = policy["meson_options"]
    rendered: list[str] = []
    for key in (
        "buildtype",
        "b_ndebug",
        "default_library",
        "b_staticpic",
        "platform",
        "tests",
        "examples",
        "enable_docs",
        "enable_kmods",
        "developer_mode",
        "prefix",
        "libdir",
    ):
        value = options[key]
        if isinstance(value, bool):
            value = "true" if value else "false"
        rendered.append(f"-D{key}={value}")
    temporary_root = source.parent.resolve()
    canonical_root = policy["reproducibility"]["canonical_build_root"]
    reproducible_c_args = [
        *options["c_args"],
        f"-ffile-prefix-map={temporary_root}={canonical_root}",
        f"-fmacro-prefix-map={temporary_root}={canonical_root}",
        f"-fdebug-prefix-map={temporary_root}={canonical_root}",
    ]
    rendered.extend(
        (
            f"-Denable_drivers={','.join(options['enable_drivers'])}",
            f"-Dc_args={shlex.join(reproducible_c_args)}",
            f"-Dcpu_instruction_set={tuple_row['cpu_instruction_set']}",
        )
    )
    return [
        sys.executable, str(meson), "setup", str(build), str(source),
        "--native-file", str(native_file), *rendered,
    ]


def run_checked(arguments: list[str], environment: dict[str, str]) -> None:
    """Run one producer command with visible, fail-closed diagnostics."""

    print("+", " ".join(arguments), flush=True)
    subprocess.run(arguments, check=True, env=environment)


def _build_metadata_output(
    arguments: list[str],
    environment: dict[str, str],
    build: Path,
    role: str,
) -> bytes:
    """Return one bounded successful build-tool metadata document."""

    with (
        tempfile.TemporaryFile() as standard_output,
        tempfile.TemporaryFile() as standard_error,
    ):
        result = subprocess.run(
            arguments,
            check=False,
            cwd=build,
            env=environment,
            stdout=standard_output,
            stderr=standard_error,
        )
        standard_output.flush()
        standard_error.flush()
        output_size = os.fstat(standard_output.fileno()).st_size
        error_size = os.fstat(standard_error.fileno()).st_size
        if (
            output_size > BUILD_METADATA_LIMIT_BYTES
            or error_size > BUILD_METADATA_LIMIT_BYTES
        ):
            raise ProducerError(f"{role} exceeds its byte bound")
        standard_output.seek(0)
        output = standard_output.read(BUILD_METADATA_LIMIT_BYTES + 1)
        standard_error.seek(0)
        diagnostic_bytes = standard_error.read(BUILD_METADATA_LIMIT_BYTES + 1)
    if result.returncode != 0:
        diagnostic = diagnostic_bytes.decode("utf-8", errors="backslashreplace")
        raise ProducerError(
            f"{role} failed with exit {result.returncode}: "
            f"{diagnostic[:FAILURE_TEXT_LIMIT]!r}"
        )
    if diagnostic_bytes:
        raise ProducerError(f"{role} emitted unexpected diagnostics")
    if not output:
        raise ProducerError(f"{role} is empty")
    return output


def _build_metadata_text(raw: bytes, role: str) -> str:
    """Decode one bounded build-tool document as strict newline text."""

    if not raw or len(raw) > BUILD_METADATA_LIMIT_BYTES:
        raise ProducerError(f"{role} is empty or oversized")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise ProducerError(f"{role} is not strict UTF-8") from error
    if "\x00" in text or "\r" in text:
        raise ProducerError(f"{role} contains a forbidden byte")
    return text


def _normalized_relative_build_path(spelling: str, role: str) -> PurePosixPath:
    """Return one exact normalized relative build path."""

    path = PurePosixPath(spelling)
    if not spelling or path.is_absolute() or path == PurePosixPath("."):
        raise ProducerError(f"{role} is not an exact relative path: {spelling!r}")
    if "." in path.parts or ".." in path.parts or path.as_posix() != spelling:
        raise ProducerError(f"{role} is not an exact relative path: {spelling!r}")
    return path


def _parse_compilation_database(
    raw: bytes,
    dpdk_source: Path,
    build: Path,
) -> dict[str, Path]:
    """Return the one source path for every strict Ninja compile row."""

    rows = _parse_json_array(raw, "Ninja compilation database")
    if not rows:
        raise ProducerError("Ninja compilation database is empty")
    exact_build = build.resolve(strict=True)
    exact_source = dpdk_source.resolve(strict=True)
    sources: dict[str, Path] = {}
    expected_keys = {"command", "directory", "file", "output"}
    for row in rows:
        if not isinstance(row, dict) or set(row) != expected_keys:
            raise ProducerError("Ninja compilation database has a malformed row")
        if any(not isinstance(row[key], str) or not row[key] for key in expected_keys):
            raise ProducerError("Ninja compilation database has an empty row value")
        if "\x00" in row["command"] or "\n" in row["command"] or "\r" in row["command"]:
            raise ProducerError("Ninja compilation command has a forbidden byte")
        try:
            directory = Path(row["directory"]).resolve(strict=True)
        except OSError as error:
            raise ProducerError("Ninja compilation directory is unavailable") from error
        if directory != exact_build:
            raise ProducerError("Ninja compilation row names a foreign directory")
        output = _normalized_relative_build_path(
            row["output"], "Ninja compilation output"
        ).as_posix()
        source = Path(row["file"])
        if not source.is_absolute():
            source = directory / source
        try:
            source = source.resolve(strict=True)
        except OSError as error:
            raise ProducerError("Ninja compilation source is unavailable") from error
        if not (source.is_relative_to(exact_source) or source.is_relative_to(exact_build)):
            raise ProducerError("Ninja compilation source escapes the verified build")
        if output in sources:
            raise ProducerError("Ninja compilation database repeats an output")
        sources[output] = source
    return sources


def _parse_ninja_dependencies(raw: bytes) -> dict[str, tuple[str, ...]]:
    """Return every valid Ninja dependency row under one strict grammar."""

    text = _build_metadata_text(raw, "Ninja dependency graph")
    lines = text.splitlines()
    dependencies: dict[str, tuple[str, ...]] = {}
    header_pattern = re.compile(
        r"(.+): #deps ([0-9]+), deps mtime -?[0-9]+ \((VALID|STALE)\)"
    )
    index = 0
    while index < len(lines):
        if lines[index] == "":
            index += 1
            continue
        match = header_pattern.fullmatch(lines[index])
        if match is None:
            raise ProducerError("Ninja dependency graph has a malformed header")
        output = _normalized_relative_build_path(
            match.group(1), "Ninja dependency output"
        ).as_posix()
        expected_count = int(match.group(2))
        if match.group(3) != "VALID":
            raise ProducerError("Ninja dependency graph contains stale evidence")
        index += 1
        rows: list[str] = []
        for _unused in range(expected_count):
            if index >= len(lines) or not lines[index].startswith("    "):
                raise ProducerError("Ninja dependency graph has a partial row")
            dependency = lines[index][4:]
            if not dependency or "\t" in dependency:
                raise ProducerError("Ninja dependency graph has an invalid path")
            rows.append(dependency)
            index += 1
        if index < len(lines) and lines[index] != "":
            raise ProducerError("Ninja dependency graph has trailing row data")
        if output in dependencies:
            raise ProducerError("Ninja dependency graph repeats an output")
        dependencies[output] = tuple(dict.fromkeys(rows))
    if not dependencies:
        raise ProducerError("Ninja dependency graph is empty")
    return dependencies


def _parse_archive_object_inputs(raw: bytes, archive: str) -> list[str]:
    """Return one static archive's exact ordered object-input paths."""

    lines = _build_metadata_text(raw, f"Ninja query for {archive}").splitlines()
    if len(lines) < 4 or lines[0] != f"{archive}:" or lines[1] != "  input: STATIC_LINKER":
        raise ProducerError(f"Ninja query for {archive} has an invalid header")
    try:
        output_index = lines.index("  outputs:", 2)
    except ValueError as error:
        raise ProducerError(f"Ninja query for {archive} has no output boundary") from error
    inputs: list[str] = []
    for line in lines[2:output_index]:
        if not line.startswith("    "):
            raise ProducerError(f"Ninja query for {archive} has a malformed input")
        path = _normalized_relative_build_path(
            line[4:], f"Ninja query input for {archive}"
        )
        if path.suffix != ".o":
            raise ProducerError(f"Ninja query for {archive} has a non-object input")
        inputs.append(path.as_posix())
    if not inputs or len(inputs) != len(set(inputs)):
        raise ProducerError(f"Ninja query for {archive} has ambiguous object inputs")
    for line in lines[output_index + 1:]:
        if not line.startswith("    ") or not line[4:]:
            raise ProducerError(f"Ninja query for {archive} has malformed output data")
    return inputs


def _parse_archive_members(raw: bytes, archive: str) -> list[str]:
    """Return one static archive's exact ordered member identities."""

    lines = _build_metadata_text(raw, f"archive member table for {archive}").splitlines()
    members: list[str] = []
    for line in lines:
        path = PurePosixPath(line)
        if (
            not line
            or path.is_absolute()
            or len(path.parts) != 1
            or path.suffix != ".o"
            or path.as_posix() != line
        ):
            raise ProducerError(f"archive {archive} has an invalid member identity")
        members.append(line)
    if not members or len(members) != len(set(members)):
        raise ProducerError(f"archive {archive} has ambiguous member identities")
    return members


def _resolve_dependency_path(spelling: str, build: Path) -> Path:
    """Resolve one Ninja dependency path against its exact build root."""

    if "\x00" in spelling or "\n" in spelling or "\r" in spelling:
        raise ProducerError("Ninja dependency path contains a forbidden byte")
    path = Path(spelling)
    if not path.is_absolute():
        path = build / path
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ProducerError("Ninja dependency path is unavailable") from error
    if not resolved.is_file():
        raise ProducerError("Ninja dependency path is not a regular file")
    return resolved


def static_closure_source_dependencies(
    policy: dict[str, Any],
    dpdk_source: Path,
    build: Path,
    environment: dict[str, str],
) -> list[Path]:
    """Derive the exact DPDK source/header set incorporated by the closure."""

    compilation_rows = _parse_compilation_database(
        _build_metadata_output(
            ["ninja", "-t", "compdb", "c_COMPILER"],
            environment,
            build,
            "Ninja compilation database",
        ),
        dpdk_source,
        build,
    )
    dependency_rows = _parse_ninja_dependencies(
        _build_metadata_output(
            ["ninja", "-t", "deps"],
            environment,
            build,
            "Ninja dependency graph",
        )
    )
    exact_source = dpdk_source.resolve(strict=True)
    exact_build = build.resolve(strict=True)
    source_dependencies: set[Path] = set()
    for archive in policy["archive_targets"]:
        archive_path = build / archive
        object_inputs = _parse_archive_object_inputs(
            _build_metadata_output(
                ["ninja", "-t", "query", archive],
                environment,
                build,
                f"Ninja query for {archive}",
            ),
            archive,
        )
        members = _parse_archive_members(
            _build_metadata_output(
                ["ar", "t", os.fspath(archive_path)],
                environment,
                build,
                f"archive member table for {archive}",
            ),
            archive,
        )
        if members != [PurePosixPath(path).name for path in object_inputs]:
            raise ProducerError(
                f"archive {archive} members disagree with its Ninja object graph"
            )
        for object_path in object_inputs:
            object_file = build / object_path
            try:
                exact_object = object_file.resolve(strict=True)
            except OSError as error:
                raise ProducerError(
                    f"archive {archive} has an unavailable object input"
                ) from error
            if not exact_object.is_file() or not exact_object.is_relative_to(exact_build):
                raise ProducerError(
                    f"archive {archive} has an unavailable object input"
                )
            compiled_source = compilation_rows.get(object_path)
            object_dependencies = dependency_rows.get(object_path)
            if compiled_source is None or object_dependencies is None:
                raise ProducerError(
                    f"archive {archive} has an object without complete build provenance"
                )
            resolved_dependencies = {
                _resolve_dependency_path(path, build)
                for path in object_dependencies
            }
            if compiled_source not in resolved_dependencies:
                raise ProducerError(
                    f"archive {archive} has an object whose source is absent from its dependency graph"
                )
            object_sources = {
                path for path in resolved_dependencies if path.is_relative_to(exact_source)
            }
            if not object_sources:
                raise ProducerError(
                    f"archive {archive} has an object without a DPDK source dependency"
                )
            source_dependencies.update(object_sources)
    if not source_dependencies:
        raise ProducerError("DPDK static closure has no source provenance")
    return sorted(source_dependencies)


def _source_attribution(path: Path) -> tuple[str, tuple[str, ...]] | None:
    """Return one source file's SPDX identity and copyright statements."""

    metadata = path.stat()
    if metadata.st_size <= 0 or metadata.st_size > ATTRIBUTION_SOURCE_LIMIT_BYTES:
        raise ProducerError("DPDK attribution source is empty or oversized")
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except UnicodeError as error:
        raise ProducerError("DPDK attribution source is not strict UTF-8") from error
    spdx: list[str] = []
    copyrights: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        for marker in ("/*", "//", "#", "*"):
            if line.startswith(marker):
                line = line[len(marker):].lstrip()
                break
        if line.endswith("*/"):
            line = line[:-2].rstrip()
        if line.startswith("SPDX-License-Identifier:"):
            spdx.append(line)
        if line.casefold().startswith("copyright"):
            copyrights.append(line)
    if not copyrights:
        return None
    if len(spdx) != 1 or len(copyrights) != len(set(copyrights)):
        raise ProducerError("DPDK attribution source has ambiguous legal metadata")
    if any(not value.isprintable() for value in (*spdx, *copyrights)):
        raise ProducerError("DPDK attribution text contains a control character")
    return spdx[0], tuple(copyrights)


def render_static_closure_notice(
    policy: dict[str, Any],
    dpdk_source: Path,
    build: Path,
    environment: dict[str, str],
) -> str:
    """Render deterministic attribution for the exact static DPDK closure."""

    exact_source = dpdk_source.resolve(strict=True)
    records: list[tuple[str, str, tuple[str, ...]]] = []
    for path in static_closure_source_dependencies(
        policy, dpdk_source, build, environment
    ):
        attribution = _source_attribution(path)
        if attribution is None:
            continue
        relative = path.relative_to(exact_source).as_posix()
        records.append((relative, attribution[0], attribution[1]))
    if not records:
        raise ProducerError("DPDK static closure produced no copyright notice")

    lines = [
        f"DPDK {policy['dependency']['version']} static closure copyright notices",
        "",
        "Generated from the exact completed Ninja object and header dependency",
        "graph for the declared KinetumDPDK static archives. Paths are relative",
        "to the verified DPDK source root. Corresponding license texts are in",
        "the adjacent dpdk directory.",
        "",
    ]
    for relative, spdx, copyrights in records:
        lines.append(relative)
        lines.append(f"  {spdx}")
        lines.extend(f"  {copyright}" for copyright in copyrights)
        lines.append("")
    return "\n".join(lines)


def verify_generated_configuration(
    policy: dict[str, Any], tuple_name: str, dpdk_source: Path, build: Path,
) -> None:
    """Pin feature detection and the unusable dynamic-PMD directory."""

    config_path = build / "rte_build_config.h"
    text = config_path.read_text(encoding="utf-8")
    expected_config_sha256 = policy["tuples"][tuple_name][
        "expected_rte_build_config_sha256"
    ]
    actual_config_sha256 = sha256_file(config_path)
    if actual_config_sha256 != expected_config_sha256:
        raise ProducerError(
            "generated DPDK configuration has the wrong identity: "
            f"expected {expected_config_sha256}, found {actual_config_sha256}"
        )
    try:
        abi_version = (dpdk_source / "ABI_VERSION").read_text(
            encoding="ascii", errors="strict"
        ).strip()
    except (OSError, UnicodeError) as error:
        raise ProducerError("DPDK ABI version identity is unavailable") from error
    if re.fullmatch(r"[0-9]+\.[0-9]+", abi_version) is None:
        raise ProducerError("DPDK ABI version identity is malformed")
    expected_defines = dict(policy["generated_config_defines"])
    pmd_path = (
        f"{policy['meson_options']['prefix']}/{policy['meson_options']['libdir']}"
        f"/dpdk/pmds-{abi_version}"
    )
    expected_defines["RTE_EAL_PMD_PATH"] = f'"{pmd_path}"'
    declarations = text.splitlines()
    for name, value in expected_defines.items():
        declaration = f"#define {name} {value}"
        if declaration not in declarations:
            raise ProducerError(f"generated DPDK configuration lacks {declaration}")
    for name in policy["forbidden_generated_config_defines"]:
        if any(line.startswith(f"#define {name} ") for line in declarations):
            raise ProducerError(
                f"generated DPDK configuration unexpectedly defines {name}"
            )


def exact_built_archives(build: Path) -> set[str]:
    """Return every DPDK archive actually emitted beneath one build tree."""

    return {
        path.relative_to(build).as_posix()
        for path in build.rglob("librte_*.a")
        if path.is_file()
    }


def verify_pmd_membership(
    policy: dict[str, Any], build: Path, environment: dict[str, str],
) -> None:
    """Require the exact PMD registration-symbol set from the declared drivers."""

    archives = [build / relative for relative in policy["archive_targets"]]
    result = subprocess.run(
        ["nm", "-A", "--defined-only", *map(str, archives)],
        check=True,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    symbols = (
        fields[-1]
        for line in result.stdout.splitlines()
        if (fields := line.rsplit(maxsplit=1))
    )
    actual = {symbol for symbol in symbols if symbol.endswith("_pmd_info")}
    expected = set(policy["pmd_info_symbols"])
    if actual != expected:
        raise ProducerError(
            f"DPDK PMD registration set mismatch: expected {sorted(expected)}, "
            f"found {sorted(actual)}"
        )


def copy_declared_headers(
    policy: dict[str, Any], meson: Path, build: Path, stage: Path,
    environment: dict[str, str],
) -> None:
    """Stage only Meson's declared public/generated header install surface."""

    result = subprocess.run(
        [sys.executable, str(meson), "introspect", "--installed", str(build)],
        check=True,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    install_map = _parse_json_object(
        result.stdout,
        "Meson installed-file map",
    )
    install_prefix = PurePosixPath(policy["meson_options"]["prefix"])
    temporary_root = build.parent.resolve()
    copied_destinations: set[PurePosixPath] = set()
    copied = 0
    for source_name, destination_name in sorted(install_map.items()):
        if not isinstance(destination_name, str):
            raise ProducerError("Meson installed-file map has a non-string destination")
        destination = PurePosixPath(destination_name)
        if not destination.is_absolute() or ".." in destination.parts:
            raise ProducerError(
                f"Meson declared an unsafe install destination: {destination_name}"
            )
        try:
            include_relative = destination.relative_to(install_prefix)
        except ValueError:
            continue
        if not include_relative.parts or include_relative.parts[0] != "include":
            continue
        if len(include_relative.parts) < 2 or include_relative.suffix != ".h":
            raise ProducerError(
                f"Meson declared a malformed public-header path: {destination_name}"
            )
        package_relative = PurePosixPath("include/dpdk").joinpath(
            *include_relative.parts[1:]
        )
        if package_relative in copied_destinations:
            raise ProducerError(
                f"Meson declared duplicate public-header ownership: {destination_name}"
            )
        copied_destinations.add(package_relative)

        source = Path(source_name)
        if not source.is_absolute() or not source.is_file():
            raise ProducerError(f"declared DPDK header is missing: {source}")
        resolved_source = source.resolve()
        try:
            resolved_source.relative_to(temporary_root)
        except ValueError as error:
            raise ProducerError(
                f"declared DPDK header escapes the verified build: {source}"
            ) from error
        target = stage / package_relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(resolved_source, target)
        copied += 1
    if copied == 0 or not (stage / "include/dpdk/rte_config.h").is_file():
        raise ProducerError("Meson exposed no complete DPDK public-header tree")


def render_package_config(
    root: Path, stage: Path, policy: dict[str, Any], tuple_name: str,
    tuple_row: dict[str, Any],
) -> None:
    """Instantiate the relocatable exact imported-target package."""

    config_directory = stage / PACKAGE_CONFIG_DIRECTORY
    config_directory.mkdir(parents=True, exist_ok=True)
    archive_rows = "\n".join(
        f'  "${{_KINETUM_DPDK_ROOT}}/lib/{Path(relative).name}"'
        for relative in policy["archive_targets"]
    )
    dynamic_rows = "\n".join(
        f'      "{library}"' for library in policy["dynamic_link_libraries"]
    )
    compile_option_rows = "\n".join(
        f'  "{option}"' for option in tuple_row["consumer_compile_options"]
    )
    replacements = {
        "@KINETUM_DPDK_VERSION@": policy["dependency"]["version"],
        "@KINETUM_DPDK_TUPLE@": tuple_name,
        "@KINETUM_DPDK_SYSTEM_PROCESSOR@": tuple_row["cmake_system_processor"],
        "@KINETUM_DPDK_ARCHIVE_ROWS@": archive_rows,
        "@KINETUM_DPDK_COMPILE_OPTION_ROWS@": compile_option_rows,
        "@KINETUM_DPDK_DYNAMIC_LINK_ROWS@": dynamic_rows,
    }
    for template_name, output_name in (
        ("KinetumDPDKConfig.cmake.in", "KinetumDPDKConfig.cmake"),
        ("KinetumDPDKConfigVersion.cmake.in", "KinetumDPDKConfigVersion.cmake"),
    ):
        text = (root / "third_party/dpdk" / template_name).read_text(
            encoding="utf-8"
        )
        for token, value in replacements.items():
            text = text.replace(token, value)
        if "@KINETUM_DPDK_" in text:
            raise ProducerError(f"unresolved package-template token in {template_name}")
        (config_directory / output_name).write_text(text, encoding="utf-8")


def copy_licenses(dpdk_source: Path, meson_source: Path, stage: Path) -> None:
    """Retain exact upstream license notices with the build dependency."""

    license_root = stage / "share/licenses/KinetumDPDK"
    shutil.copytree(dpdk_source / "license", license_root / "dpdk")
    meson_license = meson_source / "COPYING"
    if not meson_license.is_file():
        raise ProducerError("Meson release lacks its license notice")
    (license_root / "meson").mkdir(parents=True)
    shutil.copyfile(meson_license, license_root / "meson/COPYING")


def normalize_package_layout(stage: Path) -> None:
    """Normalize one complete candidate to the exact published POSIX layout.

    The candidate root remains private while bytes are under construction.
    Normalization occurs only after the manifest is complete, then makes every
    directory traversable and every regular file readable by ordinary build
    users without granting either group or other write authority.
    """

    try:
        root_metadata = stage.lstat()
    except OSError as error:
        raise ProducerError("candidate package root is not inspectable") from error
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise ProducerError("candidate package root is not a directory")

    directories: list[Path] = []
    files: list[Path] = []
    for path in sorted(stage.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            directories.append(path)
        elif stat.S_ISREG(metadata.st_mode):
            files.append(path)
        else:
            raise ProducerError(
                f"candidate package contains a non-regular entry: {path}"
            )

    for path in files:
        path.chmod(PACKAGE_FILE_MODE)
    for path in directories:
        path.chmod(PACKAGE_DIRECTORY_MODE)
    stage.chmod(PACKAGE_DIRECTORY_MODE)


def package_file_hashes(stage: Path) -> dict[str, str]:
    """Return deterministic content identities for every staged file."""

    return {
        path.relative_to(stage).as_posix(): sha256_file(path)
        for path in sorted(stage.rglob("*"))
        if path.is_file() and path.relative_to(stage) != PACKAGE_MANIFEST
    }


def package_payload_identity(files: dict[str, str]) -> str:
    """Return one canonical identity for an exact package payload map."""

    material = "".join(f"{path}:{files[path]}\n" for path in sorted(files))
    return hashlib.sha256(material.encode("ascii")).hexdigest()


def file_contains_bytes(path: Path, needle: bytes) -> bool:
    """Return whether one file contains a byte sequence across chunk boundaries."""

    overlap = b""
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            candidate = overlap + chunk
            if needle in candidate:
                return True
            overlap_length = len(needle) - 1
            overlap = candidate[-overlap_length:] if overlap_length else b""
    return False


def verify_temporary_path_absent(stage: Path, temporary_root: Path) -> None:
    """Reject a package whose bytes retain its disposable build location."""

    needle = os.fsencode(temporary_root.resolve())
    if not needle:
        raise ProducerError("temporary build root has no exact byte spelling")
    for path in sorted(stage.rglob("*")):
        if path.is_file() and file_contains_bytes(path, needle):
            raise ProducerError(
                f"published DPDK dependency retains its temporary build path: {path}"
            )


def write_build_manifest(
    stage: Path, policy: dict[str, Any], policy_sha256: str,
    tuple_name: str,
) -> None:
    """Write one path/time-independent dependency-package identity record."""

    manifest_path = stage / PACKAGE_MANIFEST
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    files = package_file_hashes(stage)
    payload_sha256 = package_payload_identity(files)
    expected_payload_sha256 = policy["tuples"][tuple_name][
        "expected_payload_sha256"
    ]
    if payload_sha256 != expected_payload_sha256:
        raise ProducerError(
            "DPDK package payload differs from the source-controlled tuple "
            f"identity: expected {expected_payload_sha256}, found {payload_sha256}"
        )
    manifest = {
        "schema_version": 1,
        "dependency_version": policy["dependency"]["version"],
        "dependency_sha256": policy["dependency"]["sha256"],
        "meson_version": policy["build_tool"]["version"],
        "meson_sha256": policy["build_tool"]["sha256"],
        "policy_sha256": policy_sha256,
        "tuple": tuple_name,
        "builder": policy["builder"],
        "meson_options": policy["meson_options"],
        "reproducibility": policy["reproducibility"],
        "tuple_configuration": policy["tuples"][tuple_name],
        "payload_sha256": payload_sha256,
        "archives": [Path(value).name for value in policy["archive_targets"]],
        "pmd_info_symbols": policy["pmd_info_symbols"],
        "dynamic_link_libraries": policy["dynamic_link_libraries"],
        "files": files,
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def manifest_matches_policy(
    manifest: dict[str, Any],
    policy: dict[str, Any],
    expected_policy_sha256: str,
    expected_tuple: str,
) -> bool:
    """Return whether manifest metadata equals one exact source policy."""

    tuple_row = policy["tuples"][expected_tuple]
    expected_fields = {
        "schema_version": 1,
        "policy_sha256": expected_policy_sha256,
        "tuple": expected_tuple,
        "dependency_version": policy["dependency"]["version"],
        "dependency_sha256": policy["dependency"]["sha256"],
        "meson_version": policy["build_tool"]["version"],
        "meson_sha256": policy["build_tool"]["sha256"],
        "builder": policy["builder"],
        "meson_options": policy["meson_options"],
        "reproducibility": policy["reproducibility"],
        "tuple_configuration": tuple_row,
        "payload_sha256": tuple_row["expected_payload_sha256"],
        "archives": [Path(value).name for value in policy["archive_targets"]],
        "pmd_info_symbols": policy["pmd_info_symbols"],
        "dynamic_link_libraries": policy["dynamic_link_libraries"],
    }
    # JSON identity distinguishes booleans, integers, and floating-point values;
    # Python container equality equates True with 1, including nested fields.
    observed_fields = {key: manifest.get(key) for key in expected_fields}
    return json.dumps(observed_fields, sort_keys=True) == json.dumps(expected_fields, sort_keys=True)


def package_payload_matches_manifest(
    prefix: Path,
    manifest_path: Path,
    files: Any,
    expected_payload_sha256: str,
    expected_owner_uid: int,
) -> bool:
    """Return whether one installed payload tree exactly matches its manifest."""

    if not isinstance(files, dict) or not files:
        return False
    actual_paths: set[str] = set()
    for path in prefix.rglob("*"):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            if (
                stat.S_IMODE(metadata.st_mode) != PACKAGE_DIRECTORY_MODE
                or metadata.st_uid != expected_owner_uid
            ):
                return False
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_owner_uid
        ):
            return False
        if stat.S_IMODE(metadata.st_mode) != PACKAGE_FILE_MODE:
            return False
        if path != manifest_path:
            actual_paths.add(path.relative_to(prefix).as_posix())
    if actual_paths != set(files):
        return False
    for relative, expected_sha256 in files.items():
        if (
            not isinstance(relative, str)
            or not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
            or any(character not in "0123456789abcdef" for character in expected_sha256)
        ):
            return False
        path = PurePosixPath(relative)
        if (
            not path.parts
            or path == PurePosixPath(".")
            or path.is_absolute()
            or ".." in path.parts
        ):
            return False
        payload = prefix / path
        metadata = payload.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != PACKAGE_FILE_MODE
            or metadata.st_uid != expected_owner_uid
        ):
            return False
        if sha256_file(payload) != expected_sha256:
            return False
    return package_payload_identity(files) == expected_payload_sha256


def _package_owner_is_trusted(owner_uid: int) -> bool:
    """Return whether root or this caller owns an immutable package tree."""

    return owner_uid == 0 or owner_uid == os.geteuid()


def verify_installed_package(
    prefix: Path,
    policy: dict[str, Any],
    expected_policy_sha256: str,
    expected_tuple: str,
) -> bool:
    """Return true only when an existing package is complete and current."""

    try:
        if prefix.resolve(strict=True) != prefix:
            return False
        prefix_metadata = prefix.lstat()
        if (
            not stat.S_ISDIR(prefix_metadata.st_mode)
            or stat.S_IMODE(prefix_metadata.st_mode) != PACKAGE_DIRECTORY_MODE
            or not _package_owner_is_trusted(prefix_metadata.st_uid)
        ):
            return False
        manifest_path = prefix / PACKAGE_MANIFEST
        manifest_metadata = manifest_path.lstat()
        if (
            not stat.S_ISREG(manifest_metadata.st_mode)
            or stat.S_IMODE(manifest_metadata.st_mode) != PACKAGE_FILE_MODE
            or manifest_metadata.st_uid != prefix_metadata.st_uid
        ):
            return False
        manifest_bytes = manifest_path.read_bytes()
        manifest = _parse_json_object(
            manifest_bytes,
            "installed KinetumDPDK manifest",
        )
        if manifest_bytes != (
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8"):
            return False
        if set(manifest) != PACKAGE_MANIFEST_KEYS:
            return False
        if not manifest_matches_policy(
            manifest, policy, expected_policy_sha256, expected_tuple
        ):
            return False
        return package_payload_matches_manifest(
            prefix,
            manifest_path,
            manifest.get("files"),
            policy["tuples"][expected_tuple]["expected_payload_sha256"],
            prefix_metadata.st_uid,
        )
    except (OSError, ProducerError):
        return False


def publish_package(
    stage: Path,
    prefix: Path,
    policy: dict[str, Any],
    policy_sha256: str,
    tuple_name: str,
) -> bool:
    """Publish one package and return whether the candidate ownership moved."""

    if not verify_installed_package(
        stage, policy, policy_sha256, tuple_name
    ):
        raise ProducerError("candidate KinetumDPDK package failed self-verification")
    if prefix.exists() or prefix.is_symlink():
        if verify_installed_package(
            prefix, policy, policy_sha256, tuple_name
        ):
            return False
        raise ProducerError(
            f"refusing to replace a non-exact dependency package: {prefix}"
        )
    try:
        _rename_no_replace(stage, prefix)
    except FileExistsError:
        if verify_installed_package(
            prefix, policy, policy_sha256, tuple_name
        ):
            return False
        raise ProducerError(
            f"dependency package race published a foreign object: {prefix}"
        ) from None
    return True


def parse_arguments() -> argparse.Namespace:
    """Parse the explicit dependency-producer command line."""

    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument(
        "--prefix",
        type=Path,
        help="explicit exact package root (default is content-addressed)",
    )
    parser.add_argument(
        "--cache-directory",
        type=Path,
        default=Path("/var/cache/kinetum/dependencies"),
        help="verified source-archive cache",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=max(1, os.cpu_count() or 1),
        help="parallel Ninja jobs",
    )
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument(
        "--verify-only",
        action="store_true",
        help="verify the installed package without downloading or building",
    )
    operation.add_argument(
        "--print-default-prefix",
        action="store_true",
        help="print the content-addressed default package root and exit",
    )
    return parser.parse_args()


def main() -> int:
    """Build, verify, and atomically publish one exact tuple package."""

    arguments = parse_arguments()
    if arguments.jobs <= 0:
        raise ProducerError("--jobs must be positive")

    root = repository_root()
    policy, policy_sha256 = load_policy(root)
    tuple_name, tuple_row = select_tuple(policy)
    version = policy["dependency"]["version"]
    default_prefix = default_package_prefix(
        version, tuple_name, policy_sha256
    )
    if arguments.print_default_prefix:
        if arguments.prefix is not None:
            raise ProducerError("--print-default-prefix does not accept --prefix")
        print(default_prefix)
        return 0

    prefix = arguments.prefix or default_prefix
    if (
        not prefix.is_absolute()
        or ".." in prefix.parts
        or prefix.absolute() != prefix
    ):
        raise ProducerError("--prefix must be one normalized absolute path")

    if arguments.verify_only:
        if not verify_installed_package(
            prefix, policy, policy_sha256, tuple_name
        ):
            raise ProducerError(f"KinetumDPDK package is absent or stale: {prefix}")
        print(f"KinetumDPDK package verified: {prefix}")
        return 0

    if verify_installed_package(prefix, policy, policy_sha256, tuple_name):
        print(f"KinetumDPDK package is already exact: {prefix}")
        return 0
    if prefix.exists() or prefix.is_symlink():
        raise ProducerError(
            f"refusing to replace a non-exact dependency package: {prefix}"
        )

    validate_builder(policy)
    apply_package_umask(policy)
    _require_renameat2()
    if (
        not arguments.cache_directory.is_absolute()
        or ".." in arguments.cache_directory.parts
        or arguments.cache_directory.absolute() != arguments.cache_directory
    ):
        raise ProducerError("--cache-directory must be one normalized absolute path")
    _prepare_exact_directory(
        arguments.cache_directory,
        "dependency cache directory",
    )
    _prepare_exact_directory(
        prefix.parent,
        "dependency package publication parent",
    )
    dependency = policy["dependency"]
    build_tool = policy["build_tool"]
    dpdk_archive = download_verified(
        dependency["url"],
        dependency["sha256"],
        arguments.cache_directory / f"dpdk-{dependency['version']}.tar.xz",
    )
    meson_archive = download_verified(
        build_tool["url"],
        build_tool["sha256"],
        arguments.cache_directory / f"meson-{build_tool['version']}.tar.gz",
    )

    stage: Path | None = None
    stage_consumed = False
    try:
        with tempfile.TemporaryDirectory(prefix="kinetum-dpdk-build-") as temporary:
            temporary_root = Path(temporary)
            environment = build_environment(policy, temporary_root)
            dpdk_source = extract_verified(
                dpdk_archive, temporary_root, dependency["archive_root"]
            )
            run_checked(
                [
                    "patch", "--batch", "--forward", "--fuzz=0", "--strip=1",
                    "--directory", str(dpdk_source),
                    "--input", str(root / DPDK_SOURCE_PATCH),
                ],
                environment,
            )
            meson_source = extract_verified(
                meson_archive, temporary_root, build_tool["archive_root"]
            )
            meson = meson_source / "meson.py"
            build = temporary_root / "build"
            native_file = temporary_root / "native.ini"
            write_meson_native_file(native_file)
            run_checked(
                meson_arguments(
                    policy, tuple_row, meson, dpdk_source, build, native_file
                ),
                environment,
            )
            run_checked(
                [
                    "ninja",
                    "-C",
                    str(build),
                    "-j",
                    str(arguments.jobs),
                    *policy["archive_targets"],
                ],
                environment,
            )

            expected_archives = set(policy["archive_targets"])
            actual_archives = exact_built_archives(build)
            if actual_archives != expected_archives:
                raise ProducerError(
                    "DPDK archive closure mismatch: "
                    f"expected {sorted(expected_archives)}, found {sorted(actual_archives)}"
                )
            shared_objects = [
                path for path in build.rglob("librte_*.so*") if path.is_file()
            ]
            if shared_objects:
                raise ProducerError(
                    "DPDK build emitted an undeclared shared-library form"
                )
            verify_generated_configuration(
                policy, tuple_name, dpdk_source, build
            )
            verify_pmd_membership(policy, build, environment)
            static_closure_notice = render_static_closure_notice(
                policy, dpdk_source, build, environment
            )

            stage = Path(
                tempfile.mkdtemp(
                    prefix=f".{prefix.name}.candidate-",
                    dir=prefix.parent,
                )
            )
            copy_declared_headers(policy, meson, build, stage, environment)
            (stage / "lib").mkdir(parents=True)
            for relative in policy["archive_targets"]:
                shutil.copyfile(build / relative, stage / "lib" / Path(relative).name)
            render_package_config(root, stage, policy, tuple_name, tuple_row)
            copy_licenses(dpdk_source, meson_source, stage)
            (stage / STATIC_CLOSURE_NOTICE).write_text(
                static_closure_notice,
                encoding="utf-8",
            )
            verify_temporary_path_absent(stage, temporary_root)
            write_build_manifest(
                stage, policy, policy_sha256, tuple_name
            )
            normalize_package_layout(stage)
        stage_consumed = publish_package(
            stage,
            prefix,
            policy,
            policy_sha256,
            tuple_name,
        )
    except BaseException as error:
        if stage is not None and not stage_consumed:
            _cleanup_directory_after_error(stage, error)
        raise

    if not stage_consumed:
        try:
            shutil.rmtree(stage)
        except OSError as error:
            raise ProducerError(
                "failed to remove redundant dependency package candidate"
            ) from error
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError, ProducerError) as error:
        print(f"build_kinetum_dpdk.py: error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
