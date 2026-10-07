"""Tests for crash-evident validation-run and fresh-artifact ownership."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kinetum_validation.process import run_owner


class TestValidationRunOwner(unittest.TestCase):
    """Exercise lock lifetime and exact fresh-directory admission."""

    def test_lock_is_exclusive_and_artifacts_survive_release(self) -> None:
        """A live owner excludes a peer and never deletes its artifact root."""
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve(strict=True)
            lock_path = parent / "validation.lock"
            output = parent / "run"
            with mock.patch.object(run_owner, "RUN_LOCK_PATH", lock_path):
                with run_owner.ValidationRunOwner.acquire(output) as owner:
                    self.assertTrue(owner.owns_directory(output))
                    child = owner.create_artifact_directory("run_001")
                    self.assertTrue(owner.owns_directory(child))
                    with self.assertRaisesRegex(RuntimeError, "global lock"):
                        run_owner.ValidationRunOwner.acquire(parent / "peer")
                self.assertTrue(output.is_dir())
                self.assertTrue(child.is_dir())
                with self.assertRaisesRegex(RuntimeError, "already exists"):
                    run_owner.ValidationRunOwner.acquire(output)

    def test_indirect_parent_and_nonatomic_child_names_reject(self) -> None:
        """Invalid paths and failed final admission leave no owned residue."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            real_parent = root / "real"
            real_parent.mkdir()
            indirect_parent = root / "indirect"
            indirect_parent.symlink_to(real_parent, target_is_directory=True)
            lock_path = root / "validation.lock"
            with mock.patch.object(run_owner, "RUN_LOCK_PATH", lock_path):
                with self.assertRaisesRegex(RuntimeError, "symlink-free"):
                    run_owner.ValidationRunOwner.acquire(indirect_parent / "run")
                with run_owner.ValidationRunOwner.acquire(real_parent / "run") as owner:
                    for name in ("", ".", "..", "nested/run", "nested\\run"):
                        with self.subTest(name=name):
                            with self.assertRaisesRegex(RuntimeError, "owned atom"):
                                owner.create_artifact_directory(name)

                failed_output = real_parent / "failed-run"
                exact_open = run_owner.os.open

                def reject_final_open(path, flags, mode=0o777, *, dir_fd=None):
                    """Reject only the descriptor open after directory creation."""
                    if path == failed_output.name and dir_fd is not None:
                        raise OSError("injected final admission failure")
                    return exact_open(path, flags, mode, dir_fd=dir_fd)

                with mock.patch.object(
                    run_owner.os, "open", side_effect=reject_final_open
                ):
                    with self.assertRaisesRegex(
                        OSError, "injected final admission failure"
                    ):
                        run_owner.ValidationRunOwner.acquire(failed_output)

                self.assertFalse(failed_output.exists())
                with run_owner.ValidationRunOwner.acquire(failed_output) as owner:
                    self.assertTrue(owner.owns_directory(failed_output))
