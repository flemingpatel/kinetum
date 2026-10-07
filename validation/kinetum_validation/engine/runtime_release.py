"""Verified installed-runtime metadata admission for validation evidence."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from typing import Any, Dict

from .json_contract import (
    EXPECTED_BUILD_FEATURES,
    EXPECTED_PLATFORM_CAPABILITIES,
    JsonContractError,
    parse_exact_json_object,
    require_bool,
    require_array,
    require_exact_keys,
    require_int,
    require_object,
    require_string,
)
from ..version_contract import canonical_product_version, read_product_version_file
from ..process.system_tools import exact_subprocess_environment


VERIFICATION_TIMEOUT_S = 60.0
_INFO_KEYS = frozenset(
    {
        "version",
        "dpdk_version",
        "tls_enabled",
        "build_features",
        "platform_capabilities",
        "prefix",
        "paths",
        "status",
        "errors",
        "runtime_payload",
        "provider_release",
        "components",
    }
)
_PATH_KEYS = frozenset({"binaries", "modules"})


def collect_runtime_release_metadata(
    runtime_root: Path, validation_root: Path
) -> Dict[str, Any]:
    """
    Admit one verified installed-runtime metadata record from a single invocation.

    Parameters
    ----------
    runtime_root : Path
        Already admitted exact installed runtime root.
    validation_root : Path
        Already admitted independent private validation-kit root.

    Returns
    -------
    Dict[str, Any]
        Exact JSON-serializable release metadata plus its source image.

    Raises
    ------
    RuntimeError
        If the exact information image cannot run or reports malformed,
        incomplete, foreign, or capability-inexact metadata.
    """
    candidate = runtime_root / "bin" / "kinetum-info"
    if not runtime_root.is_absolute() or not validation_root.is_absolute():
        raise RuntimeError("runtime release metadata requires absolute roots")
    if (
        validation_root.is_relative_to(runtime_root)
        or runtime_root.is_relative_to(validation_root)
    ):
        raise RuntimeError(
            "runtime and private validation-kit roots must be disjoint"
        )
    try:
        if (
            runtime_root.resolve(strict=True) != runtime_root
            or validation_root.resolve(strict=True) != validation_root
        ):
            raise RuntimeError("runtime release metadata roots are indirect")
    except OSError as exc:
        raise RuntimeError("runtime release metadata roots are unavailable") from exc
    try:
        exact_candidate = candidate.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("installed bin/kinetum-info is unavailable") from exc
    if (
        not candidate.is_file()
        or candidate.is_symlink()
        or exact_candidate != candidate
        or not os.access(candidate, os.X_OK)
    ):
        raise RuntimeError("installed bin/kinetum-info is not an exact regular file")
    raw_metadata = _verified_information_json(candidate, runtime_root)

    try:
        payload = parse_exact_json_object(raw_metadata, "kinetum-info --check --json")
        require_exact_keys(payload, _INFO_KEYS, "kinetum-info --check --json")
        _require_verified_runtime(payload)
        try:
            version = canonical_product_version(
                require_string(payload["version"], "kinetum-info version")
            )
        except ValueError as exc:
            raise JsonContractError("kinetum-info version is malformed") from exc
        dpdk_version = require_string(
            payload["dpdk_version"], "kinetum-info DPDK version"
        )
        tls_enabled = require_bool(
            payload["tls_enabled"], "kinetum-info TLS feature"
        )
        prefix = require_string(payload["prefix"], "kinetum-info prefix")
        if prefix != os.fspath(runtime_root):
            raise JsonContractError("kinetum-info prefix disagrees with runtime root")

        build_features = require_object(
            payload["build_features"], "kinetum-info build_features"
        )
        require_exact_keys(
            build_features,
            EXPECTED_BUILD_FEATURES,
            "kinetum-info build_features",
        )
        normalized_build = {
            key: require_bool(build_features[key], f"build feature {key}")
            for key in sorted(EXPECTED_BUILD_FEATURES)
        }
        if (
            normalized_build["axiom_mlir_dialect"]
            and not normalized_build["axiom_mlir_frontend"]
        ):
            raise JsonContractError("MLIR dialect requires the MLIR frontend")

        capability_values = require_array(
            payload["platform_capabilities"],
            "kinetum-info platform_capabilities",
        )
        capabilities = [
            require_string(value, "kinetum-info platform capability")
            for value in capability_values
        ]
        if (
            capabilities != sorted(capabilities)
            or len(capabilities) != len(set(capabilities))
            or frozenset(capabilities) != EXPECTED_PLATFORM_CAPABILITIES
        ):
            raise JsonContractError(
                "kinetum-info platform capability membership is inexact"
            )

        paths = require_object(payload["paths"], "kinetum-info paths")
        require_exact_keys(paths, _PATH_KEYS, "kinetum-info paths")
        expected_paths = _expected_runtime_paths(runtime_root)
        for key, expected in expected_paths.items():
            if require_string(paths[key], f"kinetum-info path {key}") != expected:
                raise JsonContractError(f"kinetum-info path {key} is foreign")

        _require_matching_versions(runtime_root, validation_root, version)
    except JsonContractError as exc:
        raise RuntimeError(str(exc)) from exc

    return {
        "source": os.fspath(candidate),
        "version": version,
        "dpdk_version": dpdk_version,
        "tls_enabled": tls_enabled,
        "build_features": normalized_build,
        "platform_capabilities": capabilities,
    }


def _verified_information_json(candidate: Path, runtime_root: Path) -> str:
    """Read verification and metadata from one protected held information image.

    Holding the descriptor prevents a pathname substitution between its
    metadata admission and execution. The runtime root, bin directory,
    and image share one protected owner: root or the invoking UID. A root-owned
    installation remains readable by an unprivileged caller. The independent
    private kit receives no provider-image attestation or extra fingerprint.
    """
    try:
        root_metadata = runtime_root.stat(follow_symlinks=False)
        owner = root_metadata.st_uid
        if owner not in (0, os.geteuid()):
            raise RuntimeError("runtime information directory is not owner-protected")
        for metadata in (root_metadata, candidate.parent.stat(follow_symlinks=False)):
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != owner
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise RuntimeError("runtime information directory is not owner-protected")
        descriptor = os.open(candidate, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise RuntimeError("runtime information image cannot be retained") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise RuntimeError("runtime information image is not owner-protected")
        image = f"/proc/self/fd/{descriptor}"
        try:
            result = subprocess.run(
                [image, "--check", "--json"], pass_fds=(descriptor,),
                stdin=subprocess.DEVNULL, capture_output=True, check=False,
                text=True, encoding="utf-8", errors="strict",
                timeout=VERIFICATION_TIMEOUT_S, env=exact_subprocess_environment(),
            )
        except (OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
            raise RuntimeError("installed bin/kinetum-info --check --json did not complete") from exc
        if result.returncode != 0 or result.stderr:
            raise RuntimeError("installed runtime verification failed at kinetum-info --check --json")
        return result.stdout
    except OSError as exc:
        raise RuntimeError("runtime information image metadata is unavailable") from exc
    finally:
        os.close(descriptor)


def _require_verified_runtime(payload: Dict[str, Any]) -> None:
    """Reject contradictory success metadata without duplicating artifact membership.

    The native verifier owns the complete runtime file set. This reader checks
    its reported outcomes and each component row before using the build facts.
    """
    if require_string(payload["status"], "runtime verification status") != "ok":
        raise JsonContractError("runtime verification status is not ok")
    require_int(payload["errors"], "runtime verification errors", minimum=0, maximum=0)
    for key in ("runtime_payload", "provider_release"):
        result = require_object(payload[key], key)
        require_exact_keys(result, {"verified"}, key)
        if not require_bool(result["verified"], f"{key} verified"):
            raise JsonContractError(f"{key} is not verified")
    components = require_array(payload["components"], "runtime verification components")
    if not components:
        raise JsonContractError("runtime verification components are empty")
    names: set[str] = set()
    for value in components:
        component = require_object(value, "runtime component")
        require_exact_keys(component, {"name", "present"}, "runtime component")
        name = require_string(component["name"], "runtime component name")
        if name in names:
            raise JsonContractError("runtime verification repeats a component")
        names.add(name)
        if not require_bool(component["present"], "runtime component present"):
            raise JsonContractError("runtime verification reports a missing component")


def _expected_runtime_paths(runtime_root: Path) -> Dict[str, str]:
    """Return only paths owned by the runtime under validation."""
    root = os.fspath(runtime_root)
    return {
        "binaries": f"{root}/bin",
        "modules": f"{root}/lib/modules",
    }


def _require_matching_versions(
    runtime_root: Path, validation_root: Path, reported_version: str
) -> None:
    """Require runtime, validation, and information-image versions to agree."""
    versions = []
    for label, path in (
        ("runtime", runtime_root / "VERSION"),
        ("validation", validation_root / "VERSION"),
    ):
        try:
            versions.append(read_product_version_file(path))
        except OSError as exc:
            raise JsonContractError(f"{label} VERSION is unavailable") from exc
        except ValueError as exc:
            raise JsonContractError(f"{label} VERSION is malformed") from exc
    if versions[0] != reported_version or versions[1] != reported_version:
        raise JsonContractError("runtime and validation release versions disagree")
