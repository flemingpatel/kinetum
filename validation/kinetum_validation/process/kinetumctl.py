"""Kinetumctl Wrapper - async wrapper for kinetumctl CLI.

Provides async interface to kinetumctl for:
- Applying config snapshots (with commit-confirmed support)
- Confirming pending configurations
- Rolling back to previous snapshots (full or selective)
- Querying DP stats
- Health checks
- Guardrails configuration

Uses subprocess to invoke the existing kinetumctl binary rather than
reimplementing gRPC protocol. This ensures consistency with platform tools.

Contract:
- No implicit mutation identity or result default
- Bounded process ownership and diagnostics
- Exact command/result agreement with kinetumctl_main.cpp"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import math
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..config.logger import log_info, log_error
from ..engine.json_contract import (
    JsonContractError,
    parse_exact_json_object,
    require_array,
    require_key_contract,
    require_object,
    require_string,
)
from .installation import is_symlink_free_regular_file
from .system_tools import communicate_bounded_subprocess, exact_subprocess_environment
from .telemetry import _MAX_EPOCH_ID, _MAX_CONFIG_SNAPSHOT_REVISION, StatsResult, StatsSelection
from .response_reader import (
    wire_uint,
    wire_int32,
    wire_string,
    wire_enum,
    _wire_sha256,
    message_shape,
    parse_stats_json,
    parse_cli_success,
    protobuf_uint64,
    protobuf_int64,
    read_snapshot_id,
)
from .telemetry_validation import stream_totals_are_exact


@dataclass
class ApplyConfigResult:
    """
    Result from apply_config operation.

    Attributes
    ----------
    success : bool
        Whether config was applied successfully.
    snapshot_id : str
        Snapshot ID that was applied.
    revision : int
        Exact active revision returned by the mutation.
    epoch : int
        Exact CP-allocated completed epoch.
    diagnostic : str
        Failure diagnostic; empty on success.
    """
    success: bool
    snapshot_id: str = ""
    revision: int = 0
    epoch: int = 0
    diagnostic: str = ""


@dataclass
class ConfirmResult:
    """
    Result from confirm operation.

    Attributes
    ----------
    success : bool
        Whether confirm succeeded.
    snapshot_id : str
        Confirmed snapshot ID.
    revision : int
        Exact confirmed revision.
    epoch : int
        Exact confirmed epoch.
    time_remaining_ms : int
        Time remaining before auto-rollback would have occurred.
    diagnostic : str
        Failure diagnostic; empty on success.
    """
    success: bool
    snapshot_id: str = ""
    revision: int = 0
    epoch: int = 0
    time_remaining_ms: int = 0
    diagnostic: str = ""


@dataclass
class RollbackResult:
    """
    Result from rollback operation.

    Attributes
    ----------
    success : bool
        Whether rollback succeeded.
    new_snapshot_id : str
        New snapshot ID created by rollback.
    new_revision : int
        Revision of the new snapshot.
    epoch : int
        Exact completed rollback epoch.
    diagnostic : str
        Failure diagnostic; empty on success.
    """
    success: bool
    new_snapshot_id: str = ""
    new_revision: int = 0
    epoch: int = 0
    diagnostic: str = ""


@dataclass(frozen=True)
class SnapshotModule:
    """One canonical module configuration returned by ``get-active``.

    Attributes
    ----------
    module_id : str
        Exact module identity.
    revision : int
        Module revision retained in the snapshot.
    config_blob : bytes
        Exact opaque module-policy bytes.
    content_type : str
        Informational content-type spelling.
    content_hash : str
        Lowercase SHA-256 claim over ``config_blob``.
    schema_id : str
        Optional tooling schema identity.
    """

    module_id: str
    revision: int
    config_blob: bytes
    content_type: str
    content_hash: str
    schema_id: str

    @property
    def policy_identity(self) -> Tuple[bytes, str, str, str]:
        """Return content identity without generated revision metadata."""
        return (
            self.config_blob,
            self.content_type,
            self.content_hash,
            self.schema_id,
        )


@dataclass(frozen=True)
class ActiveSnapshot:
    """One exact canonical active snapshot returned by ``get-active``.

    Attributes
    ----------
    snapshot_id : str
        Exact active snapshot identity.
    revision : int
        Snapshot content revision.
    created_unix_ms : int
        Nonnegative creation timestamp.
    modules : Tuple[SnapshotModule, ...]
        Canonically ordered module configurations.
    description : str
        Snapshot description.
    author : str
        Snapshot author.
    parent_snapshot_id : str
        Exact parent identity when one exists.
    labels : Tuple[Tuple[str, str], ...]
        Canonically ordered label projection.
    content_hash : str
        Lowercase canonical snapshot SHA-256 identity.
    """

    snapshot_id: str
    revision: int
    created_unix_ms: int
    modules: Tuple[SnapshotModule, ...]
    description: str
    author: str
    parent_snapshot_id: str
    labels: Tuple[Tuple[str, str], ...]
    content_hash: str

    def module_by_id(self) -> Dict[str, SnapshotModule]:
        """Return the already-validated unique module projection."""
        return {module.module_id: module for module in self.modules}


# Native defaults allow 4 * 30 + (1 + 2 + 4) = 127 seconds before process cleanup.
# Scenario statistics reads may impose an earlier observation deadline.
_KINETUMCTL_PROCESS_TIMEOUT_S = 150.0


def _sha256_hex(value: object, context: str) -> str:
    """Parse one exact lowercase SHA-256 hexadecimal identity."""
    digest = require_string(value, context)
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise JsonContractError(f"{context} is not a lowercase SHA-256 digest")
    return digest


def _optional_string(
    value: Dict[str, object], field_name: str, context: str
) -> str:
    """Read one protobuf-JSON string whose default may be omitted."""
    if field_name not in value:
        return ""
    return require_string(
        value[field_name], f"{context} {field_name}", allow_empty=True
    )


def _parse_active_snapshot(raw_json: str) -> ActiveSnapshot:
    """Parse one exact canonical ``GetActiveSnapshot`` success payload."""
    response = parse_cli_success(
        raw_json, frozenset({"snapshot"}), "get-active response"
    )
    snapshot = require_object(response["snapshot"], "active snapshot")
    require_key_contract(
        snapshot,
        {"snapshot_id", "content_hash"},
        {
            "revision", "created_unix_ms", "modules",
            "description", "author", "parent_snapshot_id", "labels",
        },
        "active snapshot",
    )
    revision = (
        protobuf_int64(snapshot["revision"], "active snapshot revision")
        if "revision" in snapshot else 0
    )
    created_unix_ms = (
        protobuf_int64(
            snapshot["created_unix_ms"], "active snapshot creation time"
        )
        if "created_unix_ms" in snapshot else 0
    )
    if (
        not 0 <= revision <= _MAX_CONFIG_SNAPSHOT_REVISION
        or created_unix_ms < 0
    ):
        raise JsonContractError("active snapshot scalar identity is out of range")

    modules = []
    prior_module_id = ""
    module_values = (
        require_array(snapshot["modules"], "active snapshot modules")
        if "modules" in snapshot else []
    )
    for index, item in enumerate(module_values):
        module = require_object(item, f"active snapshot module {index}")
        require_key_contract(
            module,
            {"module_id", "content_hash"},
            {"revision", "config_blob", "content_type", "schema_id"},
            f"active snapshot module {index}",
        )
        module_id = require_string(
            module["module_id"], f"active snapshot module {index} identity"
        )
        if (
            not module_id.isascii()
            or not module_id.isprintable()
            or any(character.isspace() for character in module_id)
            or prior_module_id and module_id <= prior_module_id
        ):
            raise JsonContractError("active snapshot modules are not strictly ordered")
        prior_module_id = module_id
        module_revision = (
            protobuf_int64(
                module["revision"], f"active snapshot module {index} revision"
            )
            if "revision" in module else 0
        )
        if not 0 <= module_revision <= _MAX_CONFIG_SNAPSHOT_REVISION:
            raise JsonContractError("active snapshot module revision is out of range")
        encoded_blob = _optional_string(
            module, "config_blob", f"active snapshot module {index}"
        )
        try:
            config_blob = base64.b64decode(encoded_blob, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise JsonContractError(
                "active snapshot module config_blob is not canonical base64"
            ) from exc
        if base64.b64encode(config_blob).decode("ascii") != encoded_blob:
            raise JsonContractError(
                "active snapshot module config_blob is not canonical base64"
            )
        content_hash = _sha256_hex(
            module["content_hash"],
            f"active snapshot module {index} content hash",
        )
        if hashlib.sha256(config_blob).hexdigest() != content_hash:
            raise JsonContractError(
                "active snapshot module content hash disagrees with config_blob"
            )
        modules.append(
            SnapshotModule(
                module_id=module_id,
                revision=module_revision,
                config_blob=config_blob,
                content_type=_optional_string(
                    module, "content_type", f"active snapshot module {index}"
                ),
                content_hash=content_hash,
                schema_id=_optional_string(
                    module, "schema_id", f"active snapshot module {index}"
                ),
            )
        )

    label_values: Tuple[Tuple[str, str], ...] = ()
    if "labels" in snapshot:
        labels = require_object(snapshot["labels"], "active snapshot labels")
        label_values = tuple(sorted(
            (
                require_string(key, "active snapshot label key"),
                require_string(value, f"active snapshot label {key}", allow_empty=True),
            )
            for key, value in labels.items()
        ))

    return ActiveSnapshot(
        snapshot_id=read_snapshot_id(
            snapshot["snapshot_id"], "active snapshot identity"
        ),
        revision=revision,
        created_unix_ms=created_unix_ms,
        modules=tuple(modules),
        description=_optional_string(snapshot, "description", "active snapshot"),
        author=_optional_string(snapshot, "author", "active snapshot"),
        parent_snapshot_id=_optional_string(
            snapshot, "parent_snapshot_id", "active snapshot"
        ),
        labels=label_values,
        content_hash=_sha256_hex(
            snapshot["content_hash"], "active snapshot content hash"
        ),
    )


def _is_exact_regular_file(path: Path) -> bool:
    """Return whether a supplied artifact path is canonical and symlink-free."""
    try:
        return (
            path.is_absolute()
            and path.resolve(strict=True) == path
            and is_symlink_free_regular_file(path)
        )
    except OSError:
        return False


def _parse_apply_result(raw_json: str) -> ApplyConfigResult:
    """Parse one exact successful SetConfigSnapshot response."""
    response = parse_cli_success(
        raw_json,
        frozenset({"snapshot_id", "revision", "epoch"}),
        "set-config response",
    )
    snapshot_id = read_snapshot_id(response["snapshot_id"], "set-config snapshot_id")
    revision = protobuf_int64(response["revision"], "set-config revision")
    epoch = protobuf_uint64(response["epoch"], "set-config epoch")
    if not 0 <= revision <= _MAX_CONFIG_SNAPSHOT_REVISION or not 0 < epoch <= _MAX_EPOCH_ID:
        raise JsonContractError("set-config success identity is outside its domain")
    return ApplyConfigResult(
        success=True,
        snapshot_id=snapshot_id,
        revision=revision,
        epoch=epoch,
    )


def _parse_confirm_result(raw_json: str) -> ConfirmResult:
    """Parse one exact successful ConfirmConfig response."""
    response = parse_cli_success(
        raw_json,
        frozenset(
            {"snapshot_id", "time_remaining_ms", "epoch", "revision"}
        ),
        "confirm response",
    )
    snapshot_id = read_snapshot_id(response["snapshot_id"], "confirm snapshot_id")
    revision = protobuf_int64(response["revision"], "confirm revision")
    epoch = protobuf_uint64(response["epoch"], "confirm epoch")
    remaining = protobuf_uint64(
        response["time_remaining_ms"], "confirm time_remaining_ms"
    )
    if (
        not 0 <= revision <= _MAX_CONFIG_SNAPSHOT_REVISION
        or not 0 < epoch <= _MAX_EPOCH_ID
        or remaining == 0
    ):
        raise JsonContractError("confirm success identity is outside its domain")
    return ConfirmResult(
        success=True,
        snapshot_id=snapshot_id,
        revision=revision,
        epoch=epoch,
        time_remaining_ms=remaining,
    )


def _parse_rollback_result(raw_json: str) -> RollbackResult:
    """Parse one exact successful Rollback response."""
    response = parse_cli_success(
        raw_json,
        frozenset({"new_snapshot_id", "new_revision", "epoch"}),
        "rollback response",
    )
    snapshot_id = read_snapshot_id(
        response["new_snapshot_id"], "rollback new_snapshot_id"
    )
    revision = protobuf_int64(response["new_revision"], "rollback revision")
    epoch = protobuf_uint64(response["epoch"], "rollback epoch")
    if not 0 <= revision <= _MAX_CONFIG_SNAPSHOT_REVISION or not 0 < epoch <= _MAX_EPOCH_ID:
        raise JsonContractError("rollback success identity is outside its domain")
    return RollbackResult(
        success=True,
        new_snapshot_id=snapshot_id,
        new_revision=revision,
        epoch=epoch,
    )


def parse_health_ready(text: str, service: str) -> bool:
    """Admit exact native health JSON and return only its typed readiness decision."""
    if service not in {"cp", "dp"}:
        raise ValueError("health service must be cp or dp")
    required = (
        frozenset({"status", "version", "uptime_seconds", "logging"})
        if service == "cp" else
        frozenset({"state", "status", "version", "runtime_generation",
                   "active_epoch", "active_workers", "expected_workers", "logging"})
    )
    response = message_shape(
        parse_exact_json_object(text, context="health response"),
        required, context="health response",
    )
    if not wire_string(response["version"]):
        raise ValueError("health version is empty")
    counters = frozenset({
        "accepted_records", "queue_rejections", "format_rejections",
        "unavailable_rejections", "undelivered_records", "write_failures",
        "console_failures", "truncated_records",
        "packet_thread_rejections", "delivery_timeouts",
    })
    logging = message_shape(
        response["logging"], counters | {"destination", "failure"},
        context="logging status",
    )
    for counter in counters:
        wire_uint(logging[counter])
    destination = wire_enum(logging["destination"], frozenset({
        "DESTINATION_STATE_AVAILABLE", "DESTINATION_STATE_UNAVAILABLE",
        "DESTINATION_STATE_CLOSED",
    }))
    failure = wire_string(logging["failure"])
    if (
        len(failure) > 255
        or any(ord(character) < 32 or ord(character) > 126 for character in failure)
    ):
        raise ValueError("logging destination contradicts its failure evidence")
    if (
        (destination == "DESTINATION_STATE_AVAILABLE" and failure)
        or (destination == "DESTINATION_STATE_UNAVAILABLE" and (
            not failure or wire_uint(logging["write_failures"]) == 0
        ))
    ):
        raise ValueError("logging destination contradicts its failure evidence")
    if service == "cp":
        wire_uint(response["uptime_seconds"])
        return wire_enum(response["status"], frozenset({
            "STATUS_SERVING", "STATUS_NOT_SERVING",
        })) == "STATUS_SERVING"
    status = message_shape(
        response["status"], frozenset({"code", "error_code", "message", "details"}),
        context="DP health status",
    )
    if (
        wire_int32(status["code"]) != 0
        or status["error_code"] != "ERROR_CODE_OK"
        or wire_string(status["message"])
        or wire_string(status["details"])
    ):
        raise ValueError("successful health command has no exact application success")
    state = wire_enum(response["state"], frozenset({
        "STATE_STARTING", "STATE_CONTROL_READY", "STATE_PACKET_READY",
    }))
    generation = wire_uint(response["runtime_generation"])
    epoch = wire_uint(response["active_epoch"])
    active = wire_uint(response["active_workers"], bits=32)
    expected = wire_uint(response["expected_workers"], bits=32)
    if state == "STATE_STARTING":
        if any((generation, epoch, active, expected)):
            raise ValueError("starting DP health retains runtime identity")
        return False
    if generation == 0 or generation > (1 << 32) - 1 or expected == 0:
        raise ValueError("DP health has incomplete runtime identity")
    if state == "STATE_CONTROL_READY":
        if epoch != 0 or active != 0:
            raise ValueError("control-ready DP health retains packet identity")
        return False
    if epoch == 0 or epoch > _MAX_EPOCH_ID or active != expected:
        raise ValueError("packet-ready DP health has incomplete packet ownership")
    return True


class KinetumCtl:
    """
    Async wrapper for kinetumctl CLI.

    Provides async methods to interact with kinetum_cp via the
    existing kinetumctl binary.

    Parameters
    ----------
    runtime_root : Path
        Exact installed runtime root containing bin/kinetumctl.
    endpoint : str
        CP gRPC endpoint (host:port).
    """

    def __init__(
        self,
        runtime_root: Path,
        endpoint: str = "127.0.0.1:50051",
    ) -> None:
        """Bind one exact installed CLI image and CP endpoint."""
        self.runtime_root = runtime_root
        self.endpoint = endpoint
        self._binary = runtime_root / "bin" / "kinetumctl"

    @property
    def binary_exists(self) -> bool:
        """Return whether kinetumctl is one exact installed executable."""
        try:
            exact_binary = self._binary.resolve(strict=True)
        except OSError:
            return False
        return (
            self._binary.is_absolute()
            and exact_binary == self._binary
            and is_symlink_free_regular_file(self._binary)
            and os.access(self._binary, os.X_OK)
        )

    async def _run(
        self,
        *args: str,
        timeout: float = _KINETUMCTL_PROCESS_TIMEOUT_S,
    ) -> tuple[int, str, str]:
        """
        Run kinetumctl command.

        Parameters
        ----------
        args : str
            Command arguments.
        timeout : float
            Command timeout in seconds.

        Returns
        -------
        tuple[int, str, str]
            (return_code, stdout, stderr)
        """
        cmd = [str(self._binary), "--endpoint", self.endpoint, *args]

        if not self.binary_exists:
            return (-1, "", "installed kinetumctl is not an exact executable")
        if not math.isfinite(timeout) or timeout <= 0.0:
            return (-1, "", "kinetumctl timeout is outside its exact domain")

        proc: Optional[asyncio.subprocess.Process] = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=exact_subprocess_environment(),
            )

            stdout, stderr = await communicate_bounded_subprocess(
                proc,
                timeout,
                5.0,
            )
            return_code = proc.returncode
            if return_code is None:
                return (-1, "", "kinetumctl exited without terminal status")
            standard_output = stdout.decode("utf-8") if stdout else ""
            standard_error = stderr.decode("utf-8") if stderr else ""
            if return_code != 0 and standard_output:
                return (-1, "", "failed kinetumctl emitted stdout payload")
            return return_code, standard_output, standard_error

        except asyncio.TimeoutError:
            if proc is None:
                return (-1, "", "Command timed out before process admission")
            return (-1, "", "Command timed out")

        except (OSError, RuntimeError, UnicodeError) as e:
            if proc is not None and proc.returncode is None:
                raise RuntimeError(
                    "kinetumctl subprocess ownership remains unresolved"
                ) from e
            return (-1, "", str(e))

    async def is_ready(self, service: str) -> bool:
        """Read typed CP/DP readiness; diagnostic degradation never selects the verdict.

        An unavailable command returns false for the bounded startup poll.
        A successful command with malformed JSON raises instead of inventing
        state or zero counters. The native CLI has already admitted runtime
        version and the complete response relation.
        """
        if service not in {"cp", "dp"}:
            raise ValueError("health service must be cp or dp")
        result, output, _diagnostic = await self._run(
            "--retries", "0", "health", "--service", service,
            "--format", "json", timeout=1.0,
        )
        if result != 0:
            return False
        return parse_health_ready(output, service)

    async def apply_config(
        self,
        config_file: Path,
        expected_revision: Optional[int] = None,
    ) -> ApplyConfigResult:
        """
        Apply configuration snapshot.

        Parameters
        ----------
        config_file : Path
            Path to config snapshot .pbtxt file.
        expected_revision : int, optional
            Presence-qualified active revision CAS, including zero.

        Returns
        -------
        ApplyConfigResult
            Exact completed mutation identity, or explicit failure.
        """
        if not _is_exact_regular_file(config_file):
            log_error("kinetumctl", f"config file not found: {config_file}")
            return ApplyConfigResult(
                success=False, diagnostic="config file is not exact"
            )

        log_info("kinetumctl", f"applying config: {config_file}")

        if expected_revision is not None and not (
            0 <= expected_revision <= _MAX_CONFIG_SNAPSHOT_REVISION
        ):
            return ApplyConfigResult(
                success=False, diagnostic="expected revision is outside its domain"
            )

        args = ["set-config", str(config_file)]
        if expected_revision is not None:
            args.extend(["--expected-revision", str(expected_revision)])
        args.extend(["--format", "json"])
        retcode, stdout, stderr = await self._run(*args)

        if retcode != 0:
            log_error("kinetumctl", f"failed to apply config: {stderr or stdout}")
            return ApplyConfigResult(success=False, diagnostic=stderr or stdout)

        try:
            result = _parse_apply_result(stdout)
        except (JsonContractError, TypeError, ValueError) as exc:
            log_error("kinetumctl", "set-config returned malformed success")
            return ApplyConfigResult(
                success=False,
                diagnostic=(stdout + stderr + f"\n{exc}").strip(),
            )
        log_info(
            "kinetumctl",
            f"config applied: {result.snapshot_id} epoch={result.epoch} "
            f"revision={result.revision}",
        )
        return result

    async def get_stats(self, selection: StatsSelection = StatsSelection()) -> StatsResult:
        """Query one native statistics response with the selected optional families.

        The default requests only mandatory runtime and engine observations.
        Returns the admitted response or an explicit failed observation.
        """
        log_info("kinetumctl", "querying stats...")

        args = ["stats", "--format", "json"]
        if selection.include_stage_stats:
            args.append("--stage-stats")
        if selection.include_module_metrics:
            args.append("--module-metrics")
        if selection.include_module_health:
            args.append("--module-health")
        if selection.include_worker_epoch_stats:
            args.append("--worker-epoch-stats")
        if selection.include_region_epoch_stats:
            args.append("--region-epoch-stats")
        if selection.include_boundary_epoch_stats:
            args.append("--boundary-epoch-stats")
        if selection.include_stream_stats:
            args.append("--stream-stats")
        if selection.include_storage_domain_stats:
            args.append("--storage-domain-stats")
        if selection.include_port_stats:
            args.append("--port-stats")
        if selection.include_topology_stats:
            args.append("--topology-stats")

        retcode, stdout, stderr = await self._run(*args)

        if retcode != 0:
            log_error("kinetumctl", f"failed to get stats: {stderr or stdout}")
            return StatsResult(success=False, diagnostic=stderr or stdout)

        # Parse JSON output from kinetumctl stats --format json
        result = parse_stats_json(stdout)
        if result.success and selection.include_stream_stats and not stream_totals_are_exact(result):
            return StatsResult(success=False, diagnostic="engine and selected stream totals disagree")
        if result.success and selection.include_topology_stats and result.module_context_count != sum(
            len(domain.context_instance_ids) for domain in result.module_context_domains
        ):
            return StatsResult(success=False, diagnostic="selected module-context domains omit admitted contexts")

        if not result.success:
            result.diagnostic = stdout
            log_error("kinetumctl", f"failed to parse stats JSON: {stdout[:200]}")
            return result

        log_info(
            "kinetumctl",
            f"stats: RX={result.rx_packets}, TX={result.tx_packets}, "
            f"drops={result.dropped_packets}, epoch={result.active_epoch}, "
            f"snapshot={result.active_snapshot_id}",
        )

        return result

    # =========================================================================
    # Commit-Confirmed Pattern
    # =========================================================================

    async def apply_config_with_confirm(
        self,
        config_file: Path,
        confirm_timeout_ms: int,
        expected_revision: Optional[int] = None,
    ) -> ApplyConfigResult:
        """
        Apply configuration with commit-confirmed mode.

        The configuration will auto-rollback if not confirmed within
        confirm_timeout_ms. Use confirm() to make the config permanent.
        CP requires an existing active snapshot as the rollback target;
        the TAP orchestrator applies the baseline snapshot during setup.

        Parameters
        ----------
        config_file : Path
            Path to config snapshot .pbtxt file.
        confirm_timeout_ms : int
            Timeout for confirmation in milliseconds.
            Must be > 0 to enable commit-confirmed mode.
        expected_revision : int, optional
            Presence-qualified active revision CAS, including zero.

        Returns
        -------
        ApplyConfigResult
            Result containing success, exact snapshot/revision/epoch identity,
            and commit-confirmed info.

        CLI equivalent:
            kinetumctl set-config <config_file> --confirm-timeout <ms>
        """
        if not _is_exact_regular_file(config_file):
            log_error("kinetumctl", f"config file not found: {config_file}")
            return ApplyConfigResult(success=False, diagnostic=f"file not found: {config_file}")

        if confirm_timeout_ms <= 0:
            log_error("kinetumctl", "confirm_timeout_ms must be > 0 for commit-confirmed mode")
            return ApplyConfigResult(success=False, diagnostic="invalid confirm_timeout_ms")
        if expected_revision is not None and not (
            0 <= expected_revision <= _MAX_CONFIG_SNAPSHOT_REVISION
        ):
            return ApplyConfigResult(
                success=False, diagnostic="expected revision is outside its domain"
            )

        log_info(
            "kinetumctl",
            f"applying config with commit-confirmed: {config_file} "
            f"(timeout={confirm_timeout_ms}ms)",
        )

        args = [
            "set-config", str(config_file),
            "--confirm-timeout", str(confirm_timeout_ms),
        ]
        if expected_revision is not None:
            args.extend(["--expected-revision", str(expected_revision)])
        args.extend(["--format", "json"])
        retcode, stdout, stderr = await self._run(*args)

        if retcode != 0:
            log_error("kinetumctl", f"failed to apply config: {stderr or stdout}")
            return ApplyConfigResult(
                success=False,
                diagnostic=stderr or stdout,
            )
        try:
            result = _parse_apply_result(stdout)
        except (JsonContractError, TypeError, ValueError) as exc:
            log_error("kinetumctl", "commit-confirmed apply returned malformed success")
            return ApplyConfigResult(
                success=False,
                diagnostic=(stdout + stderr + f"\n{exc}").strip(),
            )
        log_info(
            "kinetumctl",
            "commit-confirmed config applied: "
            f"{result.snapshot_id} epoch={result.epoch} revision={result.revision}",
        )
        return result

    async def confirm(
        self,
        snapshot_id: str,
        epoch: int,
        revision: int,
    ) -> ConfirmResult:
        """
        Confirm a pending configuration (commit-confirmed pattern).

        This durably records the exact terminal confirmation and prevents
        auto-rollback. The retained result remains retryable until the next
        successful epoch allocation clears it atomically.

        Parameters
        ----------
        snapshot_id : str
            Snapshot ID to confirm (must match the pending snapshot).
        epoch : int
            Exact nonzero epoch to confirm.
        revision : int
            Exact revision to confirm; zero is valid.

        Returns
        -------
        ConfirmResult
            Result containing the exact confirmed identity and remaining time.

        CLI equivalent:
            kinetumctl confirm <snapshot_id> --epoch <n> --revision <n>
        """
        try:
            read_snapshot_id(snapshot_id, "confirm snapshot_id")
        except JsonContractError:
            log_error("kinetumctl", "snapshot_id is outside the confirm domain")
            return ConfirmResult(
                success=False, diagnostic="snapshot_id is outside its domain"
            )

        if epoch <= 0 or epoch > _MAX_EPOCH_ID:
            log_error("kinetumctl", "exact nonzero epoch is required for confirm")
            return ConfirmResult(success=False, diagnostic="invalid confirm epoch")

        if revision < 0 or revision > _MAX_CONFIG_SNAPSHOT_REVISION:
            log_error("kinetumctl", "exact bounded revision is required for confirm")
            return ConfirmResult(success=False, diagnostic="invalid confirm revision")

        log_info("kinetumctl", f"confirming config: {snapshot_id}")

        args = [
            "confirm", snapshot_id,
            "--epoch", str(epoch),
            "--revision", str(revision),
            "--format", "json",
        ]

        retcode, stdout, stderr = await self._run(*args)

        if retcode != 0:
            log_error("kinetumctl", f"failed to confirm config: {stderr or stdout}")
            return ConfirmResult(success=False, diagnostic=stderr or stdout)
        try:
            result = _parse_confirm_result(stdout)
            if (
                result.snapshot_id != snapshot_id
                or result.epoch != epoch
                or result.revision != revision
            ):
                raise JsonContractError("confirmation identity does not echo the request")
        except (JsonContractError, TypeError, ValueError) as exc:
            log_error("kinetumctl", "confirm returned malformed success")
            return ConfirmResult(
                success=False,
                diagnostic=(stdout + stderr + f"\n{exc}").strip(),
            )
        log_info(
            "kinetumctl",
            f"config confirmed: {snapshot_id} "
            f"(time_remaining={result.time_remaining_ms}ms)",
        )
        return result

    # =========================================================================
    # Selective Rollback
    # =========================================================================

    async def rollback(
        self,
        snapshot_id: str,
        module_ids: Optional[List[str]] = None,
        expected_revision: Optional[int] = None,
    ) -> RollbackResult:
        """
        Rollback to a previous snapshot (full or selective).

        Parameters
        ----------
        snapshot_id : str
            Target snapshot ID to rollback to.
        module_ids : List[str], optional
            Modules to rollback (selective rollback).
            If None or empty, performs full rollback (all modules).
        expected_revision : int, optional
            Presence-qualified active revision CAS, including zero.

        Returns
        -------
        RollbackResult
            Result containing success status, new_snapshot_id, and rollback info.

        CLI equivalent:
            kinetumctl rollback <snapshot_id> [--modules <m1,m2,...>]
                [--expected-revision <n>]
        """
        try:
            read_snapshot_id(snapshot_id, "rollback snapshot_id")
        except JsonContractError:
            log_error("kinetumctl", "snapshot_id is outside the rollback domain")
            return RollbackResult(
                success=False, diagnostic="snapshot_id is outside its domain"
            )

        selective = module_ids is not None and len(module_ids) > 0
        if selective and (
            any(
                not module_id
                or not module_id.isprintable()
                or any(character.isspace() for character in module_id)
                or "," in module_id
                for module_id in module_ids
            )
            or len(set(module_ids)) != len(module_ids)
        ):
            return RollbackResult(
                success=False, diagnostic="module identities must be nonempty and unique"
            )
        if expected_revision is not None and not (
            0 <= expected_revision <= _MAX_CONFIG_SNAPSHOT_REVISION
        ):
            return RollbackResult(
                success=False, diagnostic="expected revision is outside its domain"
            )
        if selective:
            log_info("kinetumctl", f"selective rollback to {snapshot_id}: modules={module_ids}")
        else:
            log_info("kinetumctl", f"full rollback to {snapshot_id}")

        args = ["rollback", snapshot_id]
        if selective:
            args.extend(["--modules", ",".join(module_ids)])
        if expected_revision is not None:
            args.extend(["--expected-revision", str(expected_revision)])
        args.extend(["--format", "json"])

        retcode, stdout, stderr = await self._run(*args)

        if retcode != 0:
            log_error("kinetumctl", f"rollback failed: {stderr or stdout}")
            return RollbackResult(
                success=False,
                diagnostic=stderr or stdout,
            )
        try:
            result = _parse_rollback_result(stdout)
            if not selective and result.new_snapshot_id != snapshot_id:
                raise JsonContractError("full rollback did not echo target content")
        except (JsonContractError, TypeError, ValueError) as exc:
            log_error("kinetumctl", "rollback returned malformed success")
            return RollbackResult(
                success=False,
                diagnostic=(stdout + stderr + f"\n{exc}").strip(),
            )
        log_info(
            "kinetumctl",
            f"rollback succeeded: new_snapshot={result.new_snapshot_id}, "
            f"revision={result.new_revision}, epoch={result.epoch}",
        )
        return result

    async def get_active_snapshot(self) -> ActiveSnapshot:
        """Return the complete exact active configuration snapshot.

        Returns
        -------
        ActiveSnapshot
            Canonical active snapshot content admitted from one CLI result.

        Raises
        ------
        RuntimeError
            If the command or its success payload is not exact.
        """
        retcode, stdout, stderr = await self._run(
            "get-active", "--format", "json"
        )
        if retcode != 0:
            log_error(
                "kinetumctl", f"failed to get active snapshot: {stderr or stdout}"
            )
            raise RuntimeError("kinetumctl get-active failed")
        try:
            snapshot = _parse_active_snapshot(stdout)
        except (JsonContractError, TypeError, ValueError) as exc:
            raise RuntimeError("get-active returned malformed success") from exc
        log_info(
            "kinetumctl",
            f"active snapshot: {snapshot.snapshot_id} revision={snapshot.revision}",
        )
        return snapshot

    # =========================================================================
    # Guardrails Configuration
    # =========================================================================

    async def configure_guardrails(
        self,
        enabled: bool,
        poll_interval_ms: Optional[int] = None,
        evaluation_window_ms: Optional[int] = None,
        max_drop_ratio: Optional[float] = None,
        min_tx_ratio: Optional[float] = None,
        min_packets_per_window: Optional[int] = None,
    ) -> bool:
        """
        Configure guardrails policy.

        Parameters
        ----------
        enabled : bool
            Whether to enable guardrails.
        poll_interval_ms : int, optional
            Polling interval in milliseconds.
        evaluation_window_ms : int, optional
            Evaluation window in milliseconds.
        max_drop_ratio : float, optional
            Maximum drop ratio threshold (0.0-1.0).
        min_tx_ratio : float, optional
            Minimum TX ratio threshold (0.0-1.0).
        min_packets_per_window : int, optional
            Minimum packets per window for evaluation.

        Returns
        -------
        bool
            True if configuration succeeded.

        CLI equivalent:
            kinetumctl guardrails on --poll-ms <ms> --window-ms <ms>
                                      --max-drop-ratio <r> --min-tx-ratio <r>
                                      [--min-packets <n>]
            kinetumctl guardrails off
        """
        mode = "on" if enabled else "off"
        log_info("kinetumctl", f"configuring guardrails: {mode}")

        if enabled:
            missing = []
            if poll_interval_ms is None:
                missing.append("poll_interval_ms")
            if evaluation_window_ms is None:
                missing.append("evaluation_window_ms")
            if max_drop_ratio is None:
                missing.append("max_drop_ratio")
            if min_tx_ratio is None:
                missing.append("min_tx_ratio")
            if missing:
                log_error(
                    "kinetumctl",
                    f"guardrails on missing required fields: {', '.join(missing)}",
                )
                return False
        elif any(
            v is not None
            for v in (
                poll_interval_ms,
                evaluation_window_ms,
                max_drop_ratio,
                min_tx_ratio,
                min_packets_per_window,
            )
        ):
            log_error("kinetumctl", "guardrails off does not accept policy fields")
            return False

        args = ["guardrails", mode]
        if poll_interval_ms is not None:
            args.extend(["--poll-ms", str(poll_interval_ms)])
        if evaluation_window_ms is not None:
            args.extend(["--window-ms", str(evaluation_window_ms)])
        if max_drop_ratio is not None:
            args.extend(["--max-drop-ratio", str(max_drop_ratio)])
        if min_tx_ratio is not None:
            args.extend(["--min-tx-ratio", str(min_tx_ratio)])
        if min_packets_per_window is not None:
            args.extend(["--min-packets", str(min_packets_per_window)])
        args.extend(["--format", "json"])

        retcode, stdout, stderr = await self._run(*args)

        if retcode != 0:
            log_error("kinetumctl", f"failed to configure guardrails: {stderr or stdout}")
            return False
        try:
            response = parse_cli_success(
                stdout,
                frozenset({"policy_generation", "policy_hash"}),
                "guardrails response",
            )
            generation = protobuf_uint64(
                response["policy_generation"], "guardrails policy_generation"
            )
            if generation == 0:
                raise JsonContractError("guardrails generation is zero")
            _wire_sha256(response["policy_hash"])
        except (JsonContractError, TypeError, ValueError):
            log_error("kinetumctl", "guardrails returned malformed success")
            return False
        log_info("kinetumctl", f"guardrails configured: {mode}")
        return True
