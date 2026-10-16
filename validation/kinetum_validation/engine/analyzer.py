"""
Packet Analyzer - native pcap analysis for test validation.

Launches kinetum_tap_analyzer as a subprocess to parse pcap files.
Computes loss, latency, generation-tag transition, and tag distributions.
"""

from __future__ import annotations

import os
import math
import subprocess
from pathlib import Path

from ..config.types import AnalysisResult, StreamAnalysisResult
from ..process.system_tools import exact_subprocess_environment
from .json_contract import (
    JsonContractError,
    parse_exact_json_object,
    require_array,
    require_exact_keys,
    require_int,
    require_number,
    require_object,
)


_UINT64_MAX = (1 << 64) - 1
_UINT32_MAX = (1 << 32) - 1
_GENERATION_TAG_MAX = (1 << 16) - 1
_RESULT_KEYS = frozenset(
    {
        "total_rx",
        "valid",
        "invalid",
        "duplicates",
        "out_of_order",
        "transition_seq",
        "tag_transition_count",
        "max_gap",
        "loss_pct",
        "missing_count",
        "latency",
        "tag_counts",
        "streams",
    }
)
_LATENCY_KEYS = frozenset({"avg", "min", "max", "p50", "p99", "count"})
_STREAM_KEYS = frozenset({
    "stream_index", "expected_count", "valid", "duplicates", "out_of_order",
    "missing_count", "transition_seq", "tag_transition_count",
    "first_tag", "last_tag", "tag_counts",
})


def _parse_tag_counts(value: object, valid: int, label: str) -> dict[int, int]:
    """Require canonical positive tag membership covering every unique packet."""
    counts = {}
    for text, count in require_object(value, label).items():
        if not text.isascii() or not text.isdecimal():
            raise JsonContractError(f"{label} contains a malformed tag")
        tag = int(text)
        if str(tag) != text or tag > _GENERATION_TAG_MAX:
            raise JsonContractError(f"{label} contains a noncanonical tag")
        counts[tag] = require_int(count, label, minimum=1, maximum=_UINT64_MAX)
    if sum(counts.values()) != valid:
        raise JsonContractError(f"{label} does not cover the unique packets")
    return counts


def _parse_streams(value: object, expected_count: int, stream_count: int) -> tuple[StreamAnalysisResult, ...]:
    """Validate the exact input population, membership, and observed ordering."""
    values = require_array(value, "analyzer streams")
    if len(values) != stream_count:
        raise JsonContractError("analyzer stream population is not exact")
    streams = []
    for index, item in enumerate(values):
        row = require_object(item, "analyzer stream")
        require_exact_keys(row, _STREAM_KEYS, "analyzer stream")
        ordinal = require_int(row["stream_index"], "stream index", minimum=0, maximum=63)
        expected = require_int(row["expected_count"], "stream expected count", minimum=0, maximum=_UINT32_MAX)
        valid = require_int(row["valid"], "stream unique packets", minimum=0, maximum=expected)
        duplicates = require_int(row["duplicates"], "stream duplicates", minimum=0, maximum=_UINT64_MAX)
        missing = require_int(row["missing_count"], "stream missing packets", minimum=0, maximum=expected)
        out_of_order = require_int(row["out_of_order"], "stream order", minimum=0, maximum=max(0, valid - 1))
        changes = require_int(row["tag_transition_count"], "stream tag changes", minimum=0, maximum=max(0, valid - 1))
        transition = require_int(row["transition_seq"], "stream tag-change identity", minimum=-1, maximum=_UINT32_MAX)
        tags = _parse_tag_counts(row["tag_counts"], valid, "stream tag counts")
        first = None if row["first_tag"] is None else require_int(
            row["first_tag"], "stream first tag", minimum=0, maximum=_GENERATION_TAG_MAX,
        )
        last = None if row["last_tag"] is None else require_int(
            row["last_tag"], "stream last tag", minimum=0, maximum=_GENERATION_TAG_MAX,
        )
        expected_for_input = expected_count // stream_count + int(index < expected_count % stream_count)
        if ordinal != index or expected != expected_for_input or missing != expected - valid:
            raise JsonContractError("analyzer stream membership is contradictory")
        if valid == 0:
            if duplicates != 0 or first is not None or last is not None:
                raise JsonContractError("empty analyzer stream retains packet evidence")
        elif first not in tags or last not in tags or len(tags) - 1 > changes:
            raise JsonContractError("analyzer stream tag endpoints are contradictory")
        if (changes == 0) != (transition == -1) or (
            transition >= 0 and (transition >= expected_count or transition % stream_count != index)
        ):
            raise JsonContractError("analyzer stream tag-change identity is contradictory")
        if (changes == 0 and first != last) or (changes == 1 and first == last):
            raise JsonContractError("analyzer stream tag-change count is contradictory")
        streams.append(StreamAnalysisResult(
            stream_index=ordinal,
            expected_count=expected,
            valid=valid,
            duplicates=duplicates,
            out_of_order=out_of_order,
            missing_count=missing,
            transition_seq=transition,
            tag_transition_count=changes,
            first_tag=first,
            last_tag=last,
            tag_counts=tags,
        ))
    return tuple(streams)


class PacketAnalyzer:
    """
    Analyze captured packets from pcap file using the native analyzer.

    Launches kinetum_tap_analyzer as a subprocess and parses its
    JSON output into an AnalysisResult.

    Parameters
    ----------
    pcap_file : Path
        Path to pcap file.
    expected_count : int
        Expected number of packets.
    analyzer_bin : Path
        Exact installed kinetum_tap_analyzer executable.
    stream_count : int
        Exact size of the sender's ordered TAP ingress list.
    """

    def __init__(
        self,
        pcap_file: Path,
        analyzer_bin: Path,
        expected_count: int,
        stream_count: int,
    ) -> None:
        """Bind one capture and its expected packet-analysis contract."""
        self.pcap_file = pcap_file
        self.expected_count = expected_count
        self.analyzer_bin = analyzer_bin
        self.stream_count = stream_count

    def analyze(self) -> AnalysisResult:
        """
        Analyze pcap file using the native analyzer.

        Returns
        -------
        AnalysisResult
            Analysis results.
        """
        if (
            not isinstance(self.expected_count, int)
            or isinstance(self.expected_count, bool)
            or self.expected_count < 0
            or self.expected_count > _UINT32_MAX
        ):
            raise RuntimeError("native analyzer expected count is out of range")
        if (
            not isinstance(self.stream_count, int)
            or isinstance(self.stream_count, bool)
            or not 1 <= self.stream_count <= 64
        ):
            raise RuntimeError("native analyzer input population is out of range")
        try:
            exact_pcap = self.pcap_file.resolve(strict=True)
            exact_analyzer = self.analyzer_bin.resolve(strict=True)
        except OSError as exc:
            raise RuntimeError("native analyzer input is unavailable") from exc
        if (
            not self.pcap_file.is_absolute()
            or exact_pcap != self.pcap_file
            or not self.pcap_file.is_file()
            or self.pcap_file.is_symlink()
        ):
            raise RuntimeError(
                f"pcap is not an exact regular file: {self.pcap_file}"
            )
        if (
            not self.analyzer_bin.is_absolute()
            or exact_analyzer != self.analyzer_bin
            or not self.analyzer_bin.is_file()
            or self.analyzer_bin.is_symlink()
            or not os.access(self.analyzer_bin, os.X_OK)
        ):
            raise RuntimeError(
                f"native analyzer is not an exact executable: {self.analyzer_bin}"
            )

        cmd = [
            str(self.analyzer_bin),
            "--pcap", str(self.pcap_file),
            "--expected", str(self.expected_count),
            "--stream-count", str(self.stream_count),
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                check=False,
                text=True,
                encoding="utf-8",
                errors="strict",
                timeout=300,
                env=exact_subprocess_environment(),
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("native analyzer timed out (300s)") from None
        except (OSError, UnicodeError) as e:
            raise RuntimeError("native analyzer could not be executed") from e

        if proc.returncode != 0:
            raise RuntimeError(
                f"native analyzer failed with exit code {proc.returncode}"
            )

        if proc.stderr:
            raise RuntimeError("native analyzer emitted unexpected diagnostics")

        if not proc.stdout:
            raise RuntimeError("native analyzer produced no output")

        try:
            raw = parse_exact_json_object(proc.stdout, "native analyzer")
            require_exact_keys(raw, _RESULT_KEYS, "native analyzer")
            total_rx = require_int(
                raw["total_rx"], "analyzer total_rx", minimum=0,
                maximum=_UINT64_MAX,
            )
            valid = require_int(
                raw["valid"], "analyzer valid", minimum=0, maximum=_UINT64_MAX
            )
            invalid = require_int(
                raw["invalid"], "analyzer invalid", minimum=0,
                maximum=_UINT64_MAX,
            )
            duplicates = require_int(
                raw["duplicates"], "analyzer duplicates", minimum=0,
                maximum=_UINT64_MAX,
            )
            out_of_order = require_int(
                raw["out_of_order"], "analyzer out_of_order", minimum=0,
                maximum=_UINT64_MAX,
            )
            transition_seq = require_int(
                raw["transition_seq"], "analyzer transition_seq", minimum=-1,
                maximum=_UINT32_MAX,
            )
            tag_transition_count = require_int(
                raw["tag_transition_count"], "analyzer tag transition count",
                minimum=0, maximum=_UINT64_MAX,
            )
            max_gap = require_int(
                raw["max_gap"], "analyzer max_gap", minimum=0,
                maximum=_UINT64_MAX,
            )
            missing_count = require_int(
                raw["missing_count"], "analyzer missing_count", minimum=0,
                maximum=_UINT64_MAX,
            )
            loss_pct = raw["loss_pct"]
            if (
                valid + invalid + duplicates != total_rx
                or valid > self.expected_count
                or max_gap > missing_count
                or missing_count != self.expected_count - valid
                or (max_gap == 0) != (missing_count == 0)
            ):
                raise JsonContractError("native analyzer counters are contradictory")

            tag_counts = _parse_tag_counts(raw["tag_counts"], valid, "analyzer tag counts")
            streams = _parse_streams(raw["streams"], self.expected_count, self.stream_count)
            stream_tags: dict[int, int] = {}
            for stream in streams:
                for tag, count in stream.tag_counts.items():
                    stream_tags[tag] = stream_tags.get(tag, 0) + count
            if (
                sum(row.valid for row in streams) != valid
                or sum(row.duplicates for row in streams) != duplicates
                or sum(row.out_of_order for row in streams) != out_of_order
                or sum(row.missing_count for row in streams) != missing_count
                or stream_tags != tag_counts
            ):
                raise JsonContractError("analyzer totals disagree with input observations")
            first_transition = min(
                (row.transition_seq for row in streams if row.transition_seq >= 0), default=-1,
            )
            if transition_seq != first_transition or tag_transition_count != sum(
                row.tag_transition_count for row in streams
            ):
                raise JsonContractError("analyzer tag changes disagree with input observations")
            if self.expected_count == 0:
                if loss_pct is not None:
                    raise JsonContractError("analyzer loss has no sent population")
            else:
                loss_pct = require_number(loss_pct, "analyzer loss_pct", minimum=0.0, maximum=100.0)
                expected_loss = (self.expected_count - valid) / self.expected_count * 100.0
                if not math.isclose(loss_pct, expected_loss, rel_tol=1e-12, abs_tol=0.0):
                    raise JsonContractError("analyzer loss percentage is contradictory")
            if (tag_transition_count == 0) != (transition_seq == -1):
                raise JsonContractError("analyzer transition identity is contradictory")

            latency_values = None
            if valid == 0:
                if raw["latency"] is not None:
                    raise JsonContractError("empty analyzer capture retained latency measurements")
            else:
                latency = require_object(raw["latency"], "analyzer latency")
                require_exact_keys(latency, _LATENCY_KEYS, "analyzer latency")
                latency_count = require_int(latency["count"], "analyzer latency count", minimum=1, maximum=_UINT64_MAX)
                if latency_count != valid:
                    raise JsonContractError("analyzer latency membership disagrees with valid packets")
                latency_values = {
                    key: require_number(latency[key], f"analyzer latency {key}", minimum=0.0)
                    for key in ("avg", "min", "max", "p50", "p99")
                }
        except JsonContractError as exc:
            raise RuntimeError("native analyzer produced malformed evidence") from exc

        result = AnalysisResult(
            total_rx=total_rx,
            valid=valid,
            invalid=invalid,
            duplicates=duplicates,
            missing_count=missing_count,
            max_gap=max_gap,
            tag_counts=tag_counts,
            streams=streams,
        )
        if latency_values is not None:
            try:
                result.set_latency_stats(latency_values)
            except ValueError as exc:
                raise RuntimeError(
                    "native analyzer produced malformed latency evidence"
                ) from exc

        return result
