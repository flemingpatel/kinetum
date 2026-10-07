"""Exact installed-root admission shared by validation entry points."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, List


RUNTIME_EXECUTABLES = (
    "kinetum-info",
    "kinetum_cp",
    "kinetum_dp",
    "kinetum_pack",
    "kinetum_photon",
    "kinetumctl",
)

VALIDATION_EXECUTABLES = (
    "kinetum_tap_sender",
    "kinetum_tap_analyzer",
)


def is_symlink_free_directory(path: Path) -> bool:
    """Return whether path is an absolute real directory with no indirect component."""
    return (
        path.is_absolute()
        and not _path_has_symlink(path)
        and path.is_dir()
    )


def is_symlink_free_regular_file(path: Path) -> bool:
    """Return whether path is an absolute regular file with no indirect component."""
    return (
        path.is_absolute()
        and not _path_has_symlink(path)
        and path.is_file()
    )


def installed_root_errors(
    runtime_root: Path,
    validation_root: Path,
    require_modules: bool,
) -> List[str]:
    """Admit explicit runtime and disjoint private-kit inputs before a run."""
    errors: List[str] = []
    for label, root in (
        ("runtime root", runtime_root),
        ("validation root", validation_root),
    ):
        if not root.is_absolute():
            errors.append(f"{label} must be absolute: {root}")
        elif _path_has_symlink(root):
            errors.append(f"{label} must not contain symlink indirection: {root}")
        elif not root.is_dir():
            errors.append(f"{label} not found: {root}")
        else:
            try:
                if root.resolve(strict=True) != root:
                    errors.append(f"{label} must be canonical: {root}")
            except OSError:
                errors.append(f"{label} cannot be resolved exactly: {root}")

    if (
        runtime_root.is_absolute()
        and validation_root.is_absolute()
        and (
            validation_root.is_relative_to(runtime_root)
            or runtime_root.is_relative_to(validation_root)
        )
    ):
        errors.append(
            "runtime and private validation-kit roots must be disjoint"
        )

    for name in RUNTIME_EXECUTABLES:
        _require_executable(
            runtime_root / "bin" / name,
            "installed runtime binary",
            errors,
        )
    for name in VALIDATION_EXECUTABLES:
        _require_executable(
            validation_root / "bin" / name,
            "validation helper",
            errors,
        )

    _require_directory(
        validation_root / "examples",
        "validation examples directory",
        errors,
    )

    if require_modules:
        _require_directory(
            runtime_root / "lib" / "modules",
            "installed module directory",
            errors,
        )

    return errors


def installed_example_input_errors(
    validation_root: Path,
    example_dir: str,
    filenames: Iterable[str],
) -> List[str]:
    """Return every exact-path error in one selected scenario input set."""
    errors: List[str] = []
    if not _is_path_atom(example_dir):
        return ["validation example directory name is not one exact atom"]
    deployment_root = validation_root / "examples" / example_dir
    _require_directory(
        deployment_root,
        "selected validation example directory",
        errors,
    )
    for filename in filenames:
        if not _is_path_atom(filename):
            errors.append(
                f"validation example input name is not one exact atom: {filename}"
            )
            continue
        path = deployment_root / filename
        if path.is_absolute() and _path_has_symlink(path):
            errors.append(
                f"validation example input must not contain symlink indirection: {path}"
            )
        elif not is_symlink_free_regular_file(path):
            errors.append(
                f"validation example input not found as a regular file: {path}"
            )
    return errors


def _path_has_symlink(path: Path) -> bool:
    """Return whether an existing absolute path contains symlink indirection."""
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if current.is_symlink():
            return True
    return False


def _is_path_atom(value: object) -> bool:
    """Return whether one value is a bounded printable ASCII path component."""
    return (
        isinstance(value, str)
        and value not in {"", ".", ".."}
        and value.isascii()
        and len(value.encode("ascii")) <= 255
        and value.isprintable()
        and "/" not in value
        and "\\" not in value
    )


def _require_directory(path: Path, label: str, errors: List[str]) -> None:
    """Append one error unless path is an absolute symlink-free directory."""
    if path.is_absolute() and _path_has_symlink(path):
        errors.append(f"{label} must not contain symlink indirection: {path}")
        return
    if is_symlink_free_directory(path):
        return
    errors.append(f"{label} not found as a directory: {path}")


def _require_executable(path: Path, label: str, errors: List[str]) -> None:
    """Append one error unless path is an executable symlink-free regular file."""
    if path.is_absolute() and _path_has_symlink(path):
        errors.append(f"{label} must not contain symlink indirection: {path}")
        return
    if is_symlink_free_regular_file(path) and os.access(path, os.X_OK):
        return
    errors.append(f"{label} not found as an executable regular file: {path}")
