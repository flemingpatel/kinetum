"""Canonical first-release product-version admission for validation tools."""

from __future__ import annotations

import os
import stat
from pathlib import Path


MAX_VERSION_FILE_BYTES = 256


def read_product_version_file(path: Path) -> str:
    """Read one direct, bounded, LF-terminated ASCII VERSION file.

    The caller has already admitted the parent root. The 256-byte ceiling
    matches native package VERSION admission. Open the final component with
    no-follow and nonblocking flags before inspecting its descriptor, so a
    replaced entry cannot substitute a link or hang admission on a FIFO.
    Raise OSError for I/O failure and ValueError for an invalid file or value.
    """
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= MAX_VERSION_FILE_BYTES:
            raise ValueError("VERSION must be a nonempty regular file within 256 bytes")
        raw = bytearray()
        while len(raw) <= MAX_VERSION_FILE_BYTES:
            chunk = os.read(descriptor, MAX_VERSION_FILE_BYTES + 1 - len(raw))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) != metadata.st_size or len(raw) > MAX_VERSION_FILE_BYTES:
            raise ValueError("VERSION changed size or could not be read completely")
    finally:
        os.close(descriptor)
    value = raw.decode("ascii")
    if not value.endswith("\n") or value.count("\n") != 1 or "\r" in value:
        raise ValueError("VERSION must contain one LF-terminated product version")
    return canonical_product_version(value[:-1])


def canonical_product_version(value: object) -> str:
    """
    Return one canonical three-component product version with optional suffix.

    This helper validates representation only. It does not infer compatibility
    or compare version precedence.

    Parameters
    ----------
    value : object
        Candidate version value.

    Returns
    -------
    str
        Exact canonical ``major.minor.patch[-suffix|+suffix]`` spelling.

    Raises
    ------
    ValueError
        If the value does not match the source CMake version grammar.
    """
    if not isinstance(value, str):
        raise ValueError("product version must be a string")
    suffix_index = min(
        (index for index in (value.find("-"), value.find("+")) if index >= 0),
        default=len(value),
    )
    core = value[:suffix_index]
    suffix = value[suffix_index:]
    components = core.split(".")
    if len(components) != 3 or any(
        not component
        or not component.isascii()
        or not component.isdecimal()
        for component in components
    ) or (
        suffix
        and (
            len(suffix) == 1
            or any(
                not (
                    character.isascii()
                    and (character.isalnum() or character in "._-")
                )
                for character in suffix[1:]
            )
        )
    ):
        raise ValueError("product version does not match the source version grammar")
    return value
