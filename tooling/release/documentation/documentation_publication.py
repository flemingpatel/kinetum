#!/usr/bin/env python3
"""Publish generated documentation directories through one atomic owner.

The documentation producer loads this sibling by exact source path. A first
publication uses Linux ``renameat2(RENAME_NOREPLACE)``; replacement uses
``renameat2(RENAME_EXCHANGE)`` so the accepted path always names either the
prior validated tree or the new validated tree. No check-then-replace,
delete-before-publish, or non-atomic fallback exists.
"""

from __future__ import annotations

import ctypes
import os
import pathlib
import re
import shutil
import sys
import tempfile
from collections.abc import Callable
from typing import Any


AT_FDCWD = -100
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2
FAILURE_TEXT_LIMIT = 2048


class DocumentationPublicationError(RuntimeError):
    """Report one generated-directory admission or publication failure."""


class DocumentationPublicationDoubleFault(DocumentationPublicationError):
    """Retain both an originating failure and its failed recovery action."""

    def __init__(
        self,
        operation: str,
        originating_error: BaseException,
        recovery_error: BaseException,
    ) -> None:
        """Construct one bounded diagnostic while retaining both exceptions.

        Args:
            operation: Recovery operation that failed.
            originating_error: Failure that initiated cleanup or restoration.
            recovery_error: Independent failure raised by that recovery action.
        """

        self.originating_error = originating_error
        self.recovery_error = recovery_error
        super().__init__(
            f"{operation}; originating failure: {_failure_text(originating_error)}; "
            f"recovery failure: {_failure_text(recovery_error)}"
        )


def _failure_text(error: BaseException) -> str:
    """Return one bounded escaped exception identity for a terminal diagnostic."""

    text = f"{type(error).__name__}: {str(error)!r}"
    if len(text) <= FAILURE_TEXT_LIMIT:
        return text
    return text[: FAILURE_TEXT_LIMIT - 3] + "..."


def _exact_directory(path: pathlib.Path, role: str) -> pathlib.Path:
    """Require one absolute direct directory and return its exact identity.

    Raises:
        DocumentationPublicationError: The path is absent, indirect, or not a
            directory.
    """

    if not path.is_absolute():
        raise DocumentationPublicationError(f"{role} must be absolute: {path}")
    absolute = path.absolute()
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise DocumentationPublicationError(f"{role} is unavailable: {path}") from error
    if absolute != resolved or not resolved.is_dir():
        raise DocumentationPublicationError(f"{role} must be one exact directory: {path}")
    return resolved


def generated_path(output_root: pathlib.Path, name: str) -> pathlib.Path:
    """Return one admitted direct generated child beneath an exact output root.

    Raises:
        DocumentationPublicationError: The root or child name is not exact.
    """

    if not re.fullmatch(r"[A-Za-z0-9._-]+", name) or name in {".", ".."}:
        raise DocumentationPublicationError("generated child name is not one path atom")
    root = _exact_directory(output_root, "documentation output root")
    child = root / name
    if child.parent != root or child == pathlib.Path("/"):
        raise DocumentationPublicationError(
            "generated child escapes the documentation output root"
        )
    return child


def remove_directory(output_root: pathlib.Path, name: str) -> None:
    """Remove one exact generated child without following path indirection.

    Raises:
        DocumentationPublicationError: The root or existing child is not one
            direct directory.
        OSError: Exact recursive removal fails.
    """

    target = generated_path(output_root, name)
    _remove_exact_directory(target, f"generated target {name}")


def _remove_exact_directory(path: pathlib.Path, role: str) -> None:
    """Remove one direct directory or accept its exact absence.

    Raises:
        DocumentationPublicationError: An existing path is indirect or not a
            directory.
        OSError: Exact recursive removal fails.
    """

    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or not path.is_dir():
        raise DocumentationPublicationError(f"{role} is not one direct directory: {path}")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise DocumentationPublicationError(f"{role} identity is unavailable: {path}") from error
    if resolved != path:
        raise DocumentationPublicationError(f"{role} is indirect: {path}")
    shutil.rmtree(path)


def _require_renameat2() -> Any:
    """Resolve Linux ``renameat2`` from the already loaded process image.

    Raises:
        DocumentationPublicationError: The host or C library cannot provide
            the required atomic rename primitive.
    """

    if sys.platform != "linux":
        raise DocumentationPublicationError(
            "atomic documentation publication requires Linux renameat2"
        )
    process_image = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = process_image.renameat2
    except AttributeError as error:
        raise DocumentationPublicationError(
            "atomic documentation publication requires libc renameat2"
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


def _invoke_renameat2(
    left: pathlib.Path, right: pathlib.Path, flags: int
) -> None:
    """Invoke the one admitted Linux directory-rename primitive.

    Args:
        left: Exact source directory path.
        right: Exact target path in the same parent.
        flags: One admitted ``renameat2`` operation flag.

    Raises:
        DocumentationPublicationError: The operation flag or required Linux
            primitive is unavailable.
        OSError: The atomic rename operation fails.
    """

    if flags not in {RENAME_NOREPLACE, RENAME_EXCHANGE}:
        raise DocumentationPublicationError(
            "documentation rename operation flag is not admitted"
        )
    renameat2 = _require_renameat2()
    ctypes.set_errno(0)
    result = renameat2(
        AT_FDCWD,
        os.fsencode(left),
        AT_FDCWD,
        os.fsencode(right),
        flags,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        relation = "<->" if flags == RENAME_EXCHANGE else "->"
        raise OSError(
            error_number,
            os.strerror(error_number),
            f"{left} {relation} {right}",
        )


def _exchange_directories(left: pathlib.Path, right: pathlib.Path) -> None:
    """Atomically exchange two exact sibling directories without a fallback.

    Raises:
        DocumentationPublicationError: Either identity or the required Linux
            primitive is unavailable.
        OSError: The same-filesystem atomic exchange fails.
    """

    left = _exact_directory(left, "left exchange directory")
    right = _exact_directory(right, "right exchange directory")
    if left.parent != right.parent:
        raise DocumentationPublicationError(
            "documentation exchange directories must share one exact parent"
        )
    _invoke_renameat2(left, right, RENAME_EXCHANGE)


def _publish_directory_without_replacement(
    source: pathlib.Path, target: pathlib.Path
) -> None:
    """Atomically publish one exact sibling directory only when target is absent.

    Raises:
        DocumentationPublicationError: Source, parent, or target absence is not
            exact, or Linux ``renameat2`` is unavailable.
        OSError: Atomic no-replacement publication fails.
    """

    source = _exact_directory(source, "new documentation publication")
    parent = _exact_directory(target.parent, "documentation publication parent")
    if source.parent != parent or target.parent != parent:
        raise DocumentationPublicationError(
            "new documentation publication must remain within one exact parent"
        )
    if target.exists() or target.is_symlink():
        raise DocumentationPublicationError(
            f"new documentation target must be absent: {target}"
        )
    _invoke_renameat2(source, target, RENAME_NOREPLACE)


def _cleanup_after_failure(
    path: pathlib.Path,
    role: str,
    originating_error: BaseException,
) -> None:
    """Remove one rejected tree without masking the originating failure.

    Raises:
        DocumentationPublicationDoubleFault: Cleanup fails; both exceptions
            remain available on the raised object.
    """

    try:
        _remove_exact_directory(path, role)
    except BaseException as recovery_error:
        raise DocumentationPublicationDoubleFault(
            f"{role} cleanup failed",
            originating_error,
            recovery_error,
        ) from recovery_error


def _populate_candidate(
    root: pathlib.Path,
    name: str,
    populate: Callable[[pathlib.Path], None],
) -> pathlib.Path:
    """Build and validate one private same-parent candidate directory.

    Args:
        root: Exact publication parent.
        name: Canonical target name used only in the private prefix.
        populate: Complete candidate producer and prepublication validator.

    Returns:
        Exact candidate path with ownership transferred to the caller.

    Raises:
        DocumentationPublicationDoubleFault: Candidate cleanup fails while
            resolving a producer or validation failure.
        BaseException: The producer or validation failure after exact cleanup.
    """

    temporary = pathlib.Path(
        tempfile.mkdtemp(prefix=f".{name}.candidate.", dir=root)
    )
    try:
        populate(temporary)
        _exact_directory(temporary, "documentation publication candidate")
    except BaseException as originating_error:
        _cleanup_after_failure(
            temporary,
            "documentation publication candidate",
            originating_error,
        )
        raise
    return temporary


def publish_new_directory(
    output_root: pathlib.Path,
    name: str,
    populate: Callable[[pathlib.Path], None],
    validate_published: Callable[[pathlib.Path], None] | None = None,
) -> pathlib.Path:
    """Build and atomically publish one previously absent generated directory.

    Target absence is checked before candidate construction and enforced again
    by the kernel at publication. A race-created target is never replaced.

    Args:
        output_root: Exact existing owner of the generated child.
        name: Canonical direct child selected for first publication.
        populate: Candidate producer and complete prepublication validator.
        validate_published: Optional path-dependent postpublication validator.

    Returns:
        Exact path naming the new validated publication.

    Raises:
        DocumentationPublicationError: Admission or publication fails.
        DocumentationPublicationDoubleFault: Cleanup fails while resolving an
            earlier failure.
        BaseException: The exact validator failure after complete cleanup.
    """

    root = _exact_directory(output_root, "documentation output root")
    target = generated_path(root, name)
    if target.exists() or target.is_symlink():
        raise DocumentationPublicationError(
            f"new documentation target must be absent: {target}"
        )
    _require_renameat2()
    temporary = _populate_candidate(root, name, populate)
    try:
        _publish_directory_without_replacement(temporary, target)
    except BaseException as originating_error:
        _cleanup_after_failure(
            temporary,
            "documentation publication candidate",
            originating_error,
        )
        raise
    if validate_published is not None:
        try:
            validate_published(target)
        except BaseException as originating_error:
            _cleanup_after_failure(
                target,
                "rejected first documentation publication",
                originating_error,
            )
            raise
    return target


def replace_directory(
    output_root: pathlib.Path,
    name: str,
    populate: Callable[[pathlib.Path], None],
    validate_published: Callable[[pathlib.Path], None] | None = None,
) -> pathlib.Path:
    """Build, validate, and atomically publish one generated directory.

    ``populate`` must completely validate the private candidate before it
    returns. ``validate_published`` may repeat path-dependent validation after
    publication. Failure of that second check restores the prior tree before
    the originating exception is re-raised.

    Args:
        output_root: Exact existing owner of generated child directories.
        name: Canonical direct child selected for replacement.
        populate: Candidate producer and complete pre-publication validator.
        validate_published: Optional path-dependent post-publication validator.

    Returns:
        Exact path naming the new validated publication.

    Raises:
        DocumentationPublicationError: Admission, publication, or retirement
            fails.
        DocumentationPublicationDoubleFault: Cleanup or restoration fails
            while resolving an earlier failure.
        BaseException: The exact exception raised by either validator when its
            required cleanup or restoration succeeds.
    """

    root = _exact_directory(output_root, "documentation output root")
    target = generated_path(root, name)
    if not target.exists() and not target.is_symlink():
        return publish_new_directory(
            root,
            name,
            populate,
            validate_published,
        )

    _require_renameat2()
    temporary = _populate_candidate(root, name, populate)

    try:
        _exact_directory(target, "accepted documentation target")
        _exchange_directories(temporary, target)
    except BaseException as originating_error:
        _cleanup_after_failure(
            temporary,
            "documentation publication candidate",
            originating_error,
        )
        raise

    if validate_published is not None:
        try:
            validate_published(target)
        except BaseException as originating_error:
            try:
                _exchange_directories(temporary, target)
            except BaseException as recovery_error:
                raise DocumentationPublicationDoubleFault(
                    "documentation publication restoration failed",
                    originating_error,
                    recovery_error,
                ) from recovery_error
            _cleanup_after_failure(
                temporary,
                "rejected documentation publication",
                originating_error,
            )
            raise

    try:
        _remove_exact_directory(temporary, "retired documentation publication")
    except BaseException as error:
        raise DocumentationPublicationError(
            "documentation candidate is published but the prior tree could not be retired: "
            + _failure_text(error)
        ) from error
    return target
