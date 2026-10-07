"""
Packet Analyzer - native pcap analysis for test validation.

Launches kinetum_tap_analyzer as a subprocess to parse pcap files.
Computes loss, latency, generation-tag transition, and tag distributions.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from ..config.types import AnalysisResult
from ..process.system_tools import exact_subprocess_environment
from .json_contract import (
    JsonContractError,
    parse_exact_json_object,
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
    }
)
_LATENCY_KEYS = frozenset({"avg", "min", "max", "p50", "p99", "count"})


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
    """

    def __init__(
        self,
        pcap_file: Path,
        analyzer_bin: Path,
        expected_count: int,
    ) -> None:
        """Bind one capture and its expected packet-analysis contract."""
        self.pcap_file = pcap_file
        self.expected_count = expected_count
        self.analyzer_bin = analyzer_bin

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
            loss_pct = require_number(
                raw["loss_pct"], "analyzer loss_pct", minimum=0.0,
                maximum=100.0,
            )
            if (
                valid + invalid != total_rx
                or duplicates > valid
                or out_of_order > valid
                or max_gap > missing_count
            ):
                raise JsonContractError("native analyzer counters are contradictory")

            raw_tags = require_object(raw["tag_counts"], "analyzer tag_counts")
            tag_counts = {}
            for tag_text, count_value in raw_tags.items():
                if not tag_text.isascii() or not tag_text.isdecimal():
                    raise JsonContractError("analyzer generation tag is malformed")
                tag = int(tag_text)
                if str(tag) != tag_text or tag > _GENERATION_TAG_MAX:
                    raise JsonContractError("analyzer generation tag is noncanonical")
                tag_counts[tag] = require_int(
                    count_value, f"analyzer tag {tag}", minimum=0,
                    maximum=_UINT64_MAX,
                )
            if sum(tag_counts.values()) != valid:
                raise JsonContractError("analyzer tag counts do not equal valid packets")
            expected_loss = (
                (self.expected_count - valid) / self.expected_count * 100.0
                if self.expected_count > 0 and valid < self.expected_count
                else 0.0
            )
            if abs(loss_pct - expected_loss) > 0.0001:
                raise JsonContractError("analyzer loss percentage is contradictory")
            if (tag_transition_count == 0) != (transition_seq == -1):
                raise JsonContractError("analyzer transition identity is contradictory")

            latency = require_object(raw["latency"], "analyzer latency")
            require_exact_keys(latency, _LATENCY_KEYS, "analyzer latency")
            latency_count = require_int(
                latency["count"], "analyzer latency count", minimum=0,
                maximum=_UINT64_MAX,
            )
            latency_values = {
                key: require_number(
                    latency[key], f"analyzer latency {key}", minimum=0.0
                )
                for key in ("avg", "min", "max", "p50", "p99")
            }
            if latency_count != valid:
                raise JsonContractError(
                    "analyzer latency membership disagrees with valid packets"
                )
            if latency_count == 0 and any(latency_values.values()):
                raise JsonContractError("empty analyzer latency retained values")
            if latency_count > 0 and not (
                latency_values["min"] <= latency_values["p50"]
                <= latency_values["p99"] <= latency_values["max"]
                and latency_values["min"] <= latency_values["avg"]
                <= latency_values["max"]
            ):
                raise JsonContractError("analyzer latency order is contradictory")
        except JsonContractError as exc:
            raise RuntimeError("native analyzer produced malformed evidence") from exc

        result = AnalysisResult(
            total_rx=total_rx,
            valid=valid,
            invalid=invalid,
            duplicates=duplicates,
            out_of_order=out_of_order,
            missing_count=missing_count,
            tag_counts=tag_counts,
            transition_seq=transition_seq,
            tag_transition_count=tag_transition_count,
        )
        if latency_count > 0:
            try:
                result.set_latency_stats(latency_values)
            except ValueError as exc:
                raise RuntimeError(
                    "native analyzer produced malformed latency evidence"
                ) from exc

        return result
