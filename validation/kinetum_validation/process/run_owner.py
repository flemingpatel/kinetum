"""Linear ownership for one physical-validation run and its artifact root."""

from __future__ import annotations

import fcntl
import os
import stat
from pathlib import Path
from typing import Optional, Set


RUN_LOCK_PATH = Path("/run/kinetum_validation.lock")


class ValidationRunOwner:
    """Own the process-wide validation lock and fresh artifact directories."""

    def __init__(self, lock_fd: int, root_fd: int, output_root: Path) -> None:
        """Retain the acquired lock and descriptor-owned artifact root."""
        self._lock_fd: Optional[int] = lock_fd
        self._root_fd: Optional[int] = root_fd
        self.output_root = output_root
        self._owned_directories: Set[Path] = {output_root}

    @classmethod
    def acquire(cls, output_root: Path) -> "ValidationRunOwner":
        """
        Acquire the global run lock and create one fresh exact output root.

        The caller must first admit runtime and validation inputs. This method
        validates the output parent without creating it, obtains a nonblocking
        crash-released file lock, and creates only the final output component.
        """
        admitted_root, parent_fd = _admit_fresh_output_root(output_root)
        try:
            lock_fd = _acquire_run_lock()
        except BaseException:
            os.close(parent_fd)
            raise
        try:
            os.mkdir(admitted_root.name, mode=0o750, dir_fd=parent_fd)
        except FileExistsError as exc:
            os.close(parent_fd)
            os.close(lock_fd)
            raise RuntimeError(
                f"validation output root already exists: {admitted_root}"
            ) from exc
        except OSError:
            os.close(parent_fd)
            os.close(lock_fd)
            raise
        root_fd = -1
        try:
            root_fd = os.open(
                admitted_root.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            metadata = os.fstat(root_fd)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                raise RuntimeError("validation output root metadata is inexact")
        except BaseException:
            if root_fd >= 0:
                os.close(root_fd)
            try:
                os.rmdir(admitted_root.name, dir_fd=parent_fd)
            except OSError as cleanup_error:
                os.close(parent_fd)
                os.close(lock_fd)
                raise RuntimeError(
                    "failed validation output admission left an owned directory"
                ) from cleanup_error
            os.close(parent_fd)
            os.close(lock_fd)
            raise
        try:
            owner = cls(lock_fd, root_fd, admitted_root)
        except BaseException:
            os.close(root_fd)
            try:
                os.rmdir(admitted_root.name, dir_fd=parent_fd)
            except OSError as cleanup_error:
                os.close(parent_fd)
                os.close(lock_fd)
                raise RuntimeError(
                    "validation owner construction left an owned directory"
                ) from cleanup_error
            os.close(parent_fd)
            os.close(lock_fd)
            raise
        os.close(parent_fd)
        return owner

    def create_artifact_directory(self, name: str) -> Path:
        """Create and retain one fresh direct child artifact directory."""
        owner_live = self._lock_fd is not None and self._root_fd is not None
        if (
            not name
            or name in (".", "..")
            or "/" in name
            or "\\" in name
            or not owner_live
        ):
            raise RuntimeError("artifact directory name is not an owned atom")
        path = self.output_root / name
        self._owned_directories.add(path)
        try:
            os.mkdir(name, mode=0o750, dir_fd=self._root_fd)
        except FileExistsError as exc:
            self._owned_directories.discard(path)
            raise RuntimeError(f"artifact directory already exists: {path}") from exc
        except BaseException:
            self._owned_directories.discard(path)
            raise
        return path

    def owns_directory(self, path: Path) -> bool:
        """Return whether this live owner created the exact directory."""
        return self._lock_fd is not None and path in self._owned_directories

    def close(self) -> None:
        """Release the global lock after all live run resources are closed."""
        if self._lock_fd is None:
            return
        lock_fd = self._lock_fd
        root_fd = self._root_fd
        self._lock_fd = None
        self._root_fd = None
        try:
            if root_fd is not None:
                os.close(root_fd)
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

    def __enter__(self) -> "ValidationRunOwner":
        """Return this live linear owner."""
        if self._lock_fd is None:
            raise RuntimeError("validation run owner is already closed")
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        """Release the crash-evident lock without deleting artifacts."""
        self.close()


def _admit_fresh_output_root(output_root: Path) -> tuple[Path, int]:
    """Validate an absent absolute final path and retain its exact parent."""
    if (
        not output_root.is_absolute()
        or output_root != Path(os.path.normpath(output_root))
        or output_root.name in ("", ".", "..")
    ):
        raise RuntimeError("validation output root must be an absolute final path")
    if output_root.exists() or output_root.is_symlink():
        raise RuntimeError(f"validation output root already exists: {output_root}")
    try:
        parent = output_root.parent.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("validation output parent is unavailable") from exc
    if parent != output_root.parent or not parent.is_dir():
        raise RuntimeError("validation output parent must be exact and symlink-free")
    try:
        parent_fd = os.open(
            parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as exc:
        raise RuntimeError("validation output parent cannot be retained") from exc
    return parent / output_root.name, parent_fd


def _acquire_run_lock() -> int:
    """Open and exclusively lock the one process-wide validation lock file."""
    flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        lock_fd = os.open(RUN_LOCK_PATH, flags, 0o644)
    except OSError as exc:
        raise RuntimeError(f"cannot open validation run lock: {RUN_LOCK_PATH}") from exc
    try:
        metadata = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise RuntimeError("validation run lock is not one exact regular file")
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(lock_fd)
        raise RuntimeError("another physical-validation run owns the global lock") from exc
    except BaseException:
        os.close(lock_fd)
        raise
    return lock_fd
