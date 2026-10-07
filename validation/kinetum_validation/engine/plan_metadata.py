"""
Resolved plan metadata helpers for validation traffic drivers.

The validation harness treats Gluon output as runtime truth. This module reads
the small subset of generated plan.pbtxt needed by traffic drivers without
making the orchestrator own protobuf text parsing details.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..config.types import PortSpec, TrafficDriverType

_PBTXT_FIELD_RE = re.compile(
    r'^([A-Za-z_][A-Za-z0-9_]*):\s*'
    r'(?:"((?:\\.|[^"\\])*)"|([^#\s"]+))\s*(?:#.*)?$'
)
_PBTXT_MESSAGE_RE = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*|\[[^\]\r\n]+\]) \{$')
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_SIMPLE_BYTE_ESCAPES = {
    "a": 0x07,
    "b": 0x08,
    "f": 0x0C,
    "n": 0x0A,
    "r": 0x0D,
    "t": 0x09,
    "v": 0x0B,
    "\\": 0x5C,
    "'": 0x27,
    '"': 0x22,
}


@dataclass(frozen=True)
class PlanPortMetadata:
    """Exact plan fields needed to correlate logical-port telemetry."""

    logical_port_id: int
    logical_name: str
    io_driver_instance_id: str
    driver_port_id: str
    direction: str
    host_numa_node: Optional[int]
    resolved_mac_address: str


@dataclass(frozen=True)
class PlanIoStreamMetadata:
    """Exact plan fields needed to correlate executable-stream telemetry."""

    io_stream_id: str
    logical_port_id: int
    direction: str
    lane_id: str
    steering_profile_id: str
    driver_queue_id: int
    rx_storage_domain_id: Optional[str]
    tx_storage_domain_ids: Tuple[str, ...]

    @property
    def storage_domain_ids(self) -> Tuple[str, ...]:
        """Return the exact RX singleton or TX admission set."""
        if self.rx_storage_domain_id is not None:
            return (self.rx_storage_domain_id,)
        return self.tx_storage_domain_ids


@dataclass
class _GeneratedMessage:
    """Keep immediate scalar and child-message occurrences from generated text."""

    scalars: Dict[str, List[str]]
    messages: Dict[str, List[_GeneratedMessage]]


@dataclass(frozen=True)
class PlanStorageDomainMetadata:
    """Exact plan fields needed to correlate packet-storage telemetry."""

    storage_domain_id: str
    host_numa_node: Optional[int]
    buffer_count: int


@dataclass(frozen=True)
class PlanSteeringProfileMetadata:
    """Exact plan fields needed to correlate traffic-steering telemetry."""

    steering_profile_id: str
    kind: str
    stream_ids: Tuple[str, ...]


@dataclass(frozen=True)
class PlanModuleContextDomainMetadata:
    """One module's canonical context population, whose order defines ordinals."""

    module_id: str
    context_instance_ids: Tuple[str, ...]


@dataclass(frozen=True)
class PlanStorageTransitionMetadata:
    """Exact storage-domain change declared on one compiled packet edge."""

    transition_id: str
    from_storage_domain_id: str
    to_storage_domain_id: str


@dataclass(frozen=True)
class PlanTopologyMetadata:
    """Immutable plan-derived identities consumed by physical validation."""

    ports: Tuple[PlanPortMetadata, ...]
    io_streams: Tuple[PlanIoStreamMetadata, ...]
    storage_domains: Tuple[PlanStorageDomainMetadata, ...]
    steering_profiles: Tuple[PlanSteeringProfileMetadata, ...]
    module_context_domains: Tuple[PlanModuleContextDomainMetadata, ...]
    storage_transitions: Tuple[PlanStorageTransitionMetadata, ...]


def resolve_runtime_ports(
    topology: PlanTopologyMetadata,
    ports: Tuple[PortSpec, ...],
    traffic_driver: TrafficDriverType,
) -> Tuple[PortSpec, ...]:
    """Return traffic ports enriched with resolved runtime metadata."""
    plan_ports = {
        port.logical_name: port
        for port in topology.ports
    }
    updated_ports = []
    for port in ports:
        resolved = plan_ports.get(port.logical_name)
        runtime_direction = (
            normalize_plan_direction(resolved.direction)
            if resolved is not None
            else ""
        )
        if not runtime_direction:
            raise RuntimeError(
                "plan.ports[] missing supported direction for "
                f"{port.logical_name}"
            )
        if not traffic_role_matches_runtime(
            port.traffic_role,
            runtime_direction,
        ):
            raise RuntimeError(
                "traffic role does not match plan.ports[] direction for "
                f"{port.logical_name}: role={port.traffic_role} "
                f"plan={runtime_direction}"
            )
        runtime_mac = decode_resolved_mac_address(
            resolved.resolved_mac_address
            if resolved is not None
            else ""
        )
        if (
            traffic_driver == TrafficDriverType.TREX
            and port.traffic_role == "rx"
            and not runtime_mac
        ):
            raise RuntimeError(
                "plan.ports[] missing resolved_mac_address for TRex RX port "
                f"{port.logical_name}"
            )
        updated_ports.append(
            replace(
                port,
                runtime_direction=runtime_direction,
                runtime_mac=runtime_mac,
            )
        )
    return tuple(updated_ports)


def parse_plan_topology(plan_file: Path) -> PlanTopologyMetadata:
    """
    Parse the exact plan identities consumed by physical evidence checks.

    The harness does not rederive Gluon IDs or provider graph semantics. It
    reads generated identities and direction-specific storage bindings,
    then compares runtime telemetry with those emitted facts.
    """
    lines = plan_file.read_text(encoding="utf-8").splitlines()
    ports = tuple(
        PlanPortMetadata(
            logical_port_id=_uint32_scalar(record, "logical_port_id", "ports"),
            logical_name=_required_scalar(record, "logical_name", "ports"),
            io_driver_instance_id=_required_scalar(
                record,
                "io_driver_instance_id",
                "ports",
            ),
            driver_port_id=_required_scalar(record, "driver_port_id", "ports"),
            direction=_required_scalar(record, "direction", "ports"),
            host_numa_node=_optional_int(record, "host_numa_node", "ports"),
            resolved_mac_address=_optional_scalar(
                record,
                "resolved_mac_address",
                "ports",
            ),
        )
        for record in _parse_top_level_records(lines, "ports")
    )
    io_streams = tuple(
        _read_io_stream(record)
        for record in _parse_top_level_records(lines, "io_streams")
    )
    storage_domains = tuple(
        PlanStorageDomainMetadata(
            storage_domain_id=_required_scalar(
                record,
                "storage_domain_id",
                "packet_storage_domains",
            ),
            host_numa_node=_optional_int(
                record,
                "host_numa_node",
                "packet_storage_domains",
            ),
            buffer_count=_uint32_scalar(
                record,
                "buffer_count",
                "packet_storage_domains",
                minimum=1,
            ),
        )
        for record in _parse_top_level_records(
            lines,
            "packet_storage_domains",
        )
    )
    steering_profiles = tuple(
        PlanSteeringProfileMetadata(
            steering_profile_id=_required_scalar(
                record,
                "steering_profile_id",
                "traffic_steering_profiles",
            ),
            kind=_required_scalar(
                record,
                "kind",
                "traffic_steering_profiles",
            ),
            stream_ids=tuple(record.scalars.get("stream_ids", [])),
        )
        for record in _parse_top_level_records(
            lines,
            "traffic_steering_profiles",
        )
    )
    module_context_domains = tuple(
        PlanModuleContextDomainMetadata(
            module_id=_required_scalar(
                record,
                "module_id",
                "module_context_domains",
            ),
            context_instance_ids=tuple(
                record.scalars.get("context_instance_ids", [])
            ),
        )
        for record in _parse_top_level_records(
            lines,
            "module_context_domains",
        )
    )
    previous_module = ""
    contexts = set()
    for domain in module_context_domains:
        identities = domain.context_instance_ids
        if (
            domain.module_id <= previous_module
            or not identities
            or any(not identity for identity in identities)
            or tuple(sorted(set(identities))) != identities
            or contexts.intersection(identities)
        ):
            raise RuntimeError("plan.module_context_domains[] has noncanonical context membership")
        previous_module = domain.module_id
        contexts.update(identities)
    return PlanTopologyMetadata(
        ports=ports,
        io_streams=io_streams,
        storage_domains=storage_domains,
        steering_profiles=steering_profiles,
        module_context_domains=module_context_domains,
        storage_transitions=tuple(
            PlanStorageTransitionMetadata(
                transition_id=_required_scalar(record, "transition_id", "storage_transitions"),
                from_storage_domain_id=_required_scalar(
                    record, "from_storage_domain_id", "storage_transitions"
                ),
                to_storage_domain_id=_required_scalar(
                    record, "to_storage_domain_id", "storage_transitions"
                ),
            )
            for record in _parse_top_level_records(lines, "storage_transitions")
        ),
    )


def _read_io_stream(record: _GeneratedMessage) -> PlanIoStreamMetadata:
    """Read one direction-correct storage arm, rejecting malformed or mixed arms.

    The native plan already owns graph admission. This reader preserves the
    exact generated RX identity or canonical TX set for evidence comparison.
    """
    direction = _required_scalar(record, "direction", "io_streams")
    has_rx = "rx_storage_domain_id" in record.scalars
    tx_messages = record.messages.get("tx_storage", [])
    rx_domain: Optional[str] = None
    tx_domains: Tuple[str, ...] = ()
    if "storage_domain_id" in record.scalars or "storage_domain_id" in record.messages:
        raise RuntimeError("plan.io_streams[] contains removed storage_domain_id")
    if "tx_storage" in record.scalars or "rx_storage_domain_id" in record.messages:
        raise RuntimeError("plan.io_streams[] has a malformed storage arm")
    if direction == "IO_STREAM_DIRECTION_RX":
        if not has_rx or tx_messages:
            raise RuntimeError("plan.io_streams[] RX requires only its allocation storage arm")
        rx_domain = _required_scalar(record, "rx_storage_domain_id", "io_streams")
    elif direction == "IO_STREAM_DIRECTION_TX":
        if has_rx or len(tx_messages) != 1:
            raise RuntimeError("plan.io_streams[] TX requires exactly one storage admission arm")
        if tx_messages[0].messages or set(tx_messages[0].scalars) != {"storage_domain_ids"}:
            raise RuntimeError("plan.io_streams[] TX storage has undeclared fields")
        tx_domains = tuple(tx_messages[0].scalars.get("storage_domain_ids", []))
        if (
            not tx_domains
            or any(not domain for domain in tx_domains)
            or tuple(sorted(set(tx_domains))) != tx_domains
        ):
            raise RuntimeError("plan.io_streams[] TX storage domains must be nonempty, sorted, and unique")
    else:
        raise RuntimeError("plan.io_streams[] has an unsupported direction")
    return PlanIoStreamMetadata(
        io_stream_id=_required_scalar(record, "io_stream_id", "io_streams"),
        logical_port_id=_uint32_scalar(record, "logical_port_id", "io_streams"),
        direction=direction,
        lane_id=_required_scalar(record, "lane_id", "io_streams"),
        steering_profile_id=_optional_scalar(record, "steering_profile_id", "io_streams"),
        driver_queue_id=_uint32_scalar(record, "driver_queue_id", "io_streams"),
        rx_storage_domain_id=rx_domain,
        tx_storage_domain_ids=tx_domains,
    )


def decode_resolved_mac_address(encoded: str) -> str:
    """
    Decode one protobuf text-format bytes literal into canonical MAC text.

    Gluon emits ``resolved_mac_address`` as an exact six-byte plan fact.
    Text-format printers preserve printable bytes and escape the rest using
    C-style simple, octal, or hexadecimal escapes. The validation harness
    decodes only that grammar and rejects every malformed or non-six-byte
    value rather than accepting a second textual MAC contract.
    """
    if not encoded:
        return ""

    decoded = bytearray()
    index = 0
    while index < len(encoded):
        character = encoded[index]
        if character != "\\":
            value = ord(character)
            if value > 0x7F:
                raise RuntimeError(
                    "plan.ports[] resolved_mac_address contains "
                    "non-ASCII unescaped text"
                )
            decoded.append(value)
            index += 1
            continue

        index += 1
        if index >= len(encoded):
            raise RuntimeError(
                "plan.ports[] resolved_mac_address ends with an escape prefix"
            )

        escape = encoded[index]
        if escape in _SIMPLE_BYTE_ESCAPES:
            decoded.append(_SIMPLE_BYTE_ESCAPES[escape])
            index += 1
            continue

        if escape in "01234567":
            end = index + 1
            while end < len(encoded) and end < index + 3:
                if encoded[end] not in "01234567":
                    break
                end += 1
            value = int(encoded[index:end], 8)
            if value > 0xFF:
                raise RuntimeError(
                    "plan.ports[] resolved_mac_address has an out-of-range "
                    "octal escape"
                )
            decoded.append(value)
            index = end
            continue

        if escape in ("x", "X"):
            end = index + 3
            if (
                end > len(encoded)
                or len(encoded[index + 1:end]) != 2
                or any(
                    digit not in _HEX_DIGITS
                    for digit in encoded[index + 1:end]
                )
            ):
                raise RuntimeError(
                    "plan.ports[] resolved_mac_address has a malformed "
                    "hexadecimal escape"
                )
            decoded.append(int(encoded[index + 1:end], 16))
            index = end
            continue

        raise RuntimeError(
            "plan.ports[] resolved_mac_address has an unsupported escape"
        )

    if len(decoded) != 6:
        raise RuntimeError(
            "plan.ports[] resolved_mac_address must contain exactly 6 bytes"
        )
    return ":".join(f"{value:02x}" for value in decoded)


def normalize_plan_direction(value: str) -> str:
    """Convert a PortDirection enum token from plan.pbtxt into a role string."""
    if value == "PORT_DIRECTION_RX_ONLY":
        return "rx"
    if value == "PORT_DIRECTION_TX_ONLY":
        return "tx"
    if value == "PORT_DIRECTION_BIDIRECTIONAL":
        return "bidirectional"
    return ""


def traffic_role_matches_runtime(traffic_role: str, runtime_direction: str) -> bool:
    """Return whether a traffic-driver role is legal for the runtime direction."""
    if runtime_direction == "bidirectional":
        return traffic_role in ("rx", "tx")
    return traffic_role == runtime_direction


def _parse_top_level_records(
    lines: List[str],
    field_name: str,
) -> List[_GeneratedMessage]:
    """
    Return structured fields from generated top-level message records.

    The protobuf text printer emits top-level record delimiters at column zero
    and indents every record member by two spaces. Matching that exact output
    shape avoids treating braces inside quoted string or bytes values as
    structural delimiters and prevents nested messages with the same field
    name from becoming top-level records.
    """
    records: List[_GeneratedMessage] = []
    current: List[str] = []
    collecting = False
    opener = f"{field_name} {{"

    for raw_line in lines:
        if not collecting:
            if raw_line == opener:
                collecting = True
                current = []
            continue

        if raw_line == "}":
            records.append(_parse_generated_message(current))
            collecting = False
            current = []
            continue
        if not raw_line.startswith("  "):
            raise RuntimeError(
                f"malformed generated plan.{field_name}[] indentation"
            )
        current.append(raw_line[2:])

    if collecting:
        raise RuntimeError(f"unterminated plan.{field_name}[] record")
    return records


def _parse_generated_message(lines: List[str]) -> _GeneratedMessage:
    """Parse generated indentation without flattening nested names or quoted braces.

    An explicit stack walks each line once. Field occurrences remain separate
    so consumers can reject duplicates and enforce presence. Malformed scalar
    text, indentation, or message closure raises RuntimeError.
    """
    root = _GeneratedMessage({}, {})
    stack = [root]
    for line in lines:
        indent = len(line) - len(line.lstrip(" "))
        content = line[indent:]
        if not content or content.startswith("#"):
            continue
        if indent % 2:
            raise RuntimeError("malformed generated plan message indentation")
        depth = indent // 2
        if content == "}":
            if len(stack) < 2 or depth != len(stack) - 2:
                raise RuntimeError("malformed generated plan message closure")
            stack.pop()
            continue
        if depth != len(stack) - 1:
            raise RuntimeError("malformed generated plan nested-message indentation")
        opener = _PBTXT_MESSAGE_RE.fullmatch(content)
        if opener is not None:
            child = _GeneratedMessage({}, {})
            stack[-1].messages.setdefault(opener.group(1), []).append(child)
            stack.append(child)
            continue
        match = _PBTXT_FIELD_RE.fullmatch(content)
        if match is None:
            field_name = content[:64].split(":", 1)[0]
            raise RuntimeError(f"malformed generated plan scalar field {field_name}")
        value = match.group(2) if match.group(2) is not None else match.group(3)
        stack[-1].scalars.setdefault(match.group(1), []).append(value)
    if len(stack) != 1:
        raise RuntimeError("unterminated generated plan nested message")
    return root


def _required_scalar(
    record: _GeneratedMessage,
    field_name: str,
    record_name: str,
) -> str:
    """Return one required scalar field or reject malformed generated text."""
    if field_name in record.messages:
        raise RuntimeError(f"plan.{record_name}[] {field_name} must be a scalar")
    values = record.scalars.get(field_name, [])
    if len(values) != 1 or not values[0]:
        raise RuntimeError(
            f"plan.{record_name}[] requires exactly one nonempty {field_name}"
        )
    return values[0]


def _optional_scalar(
    record: _GeneratedMessage,
    field_name: str,
    record_name: str,
) -> str:
    """Return one optional scalar field or reject duplicate occurrences."""
    if field_name in record.messages:
        raise RuntimeError(f"plan.{record_name}[] {field_name} must be a scalar")
    values = record.scalars.get(field_name, [])
    if len(values) > 1:
        raise RuntimeError(
            f"plan.{record_name}[] contains duplicate {field_name}"
        )
    return values[0] if values else ""


def _uint32_scalar(
    record: _GeneratedMessage,
    field_name: str,
    record_name: str,
    *,
    minimum: int = 0,
) -> int:
    """
    Decode a proto3 uint32 scalar and enforce its admitted minimum.

    Omission encodes zero. Explicit empty or duplicate values still reject;
    a positive minimum excludes an absent or zero-valued required capacity.
    """
    if field_name in record.messages:
        raise RuntimeError(f"plan.{record_name}[] {field_name} must be a scalar")
    value = (
        _required_scalar(record, field_name, record_name)
        if field_name in record.scalars
        else "0"
    )
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise RuntimeError(
            f"plan.{record_name}[] has non-integer {field_name}"
        ) from error
    if not minimum <= parsed <= (1 << 32) - 1:
        raise RuntimeError(
            f"plan.{record_name}[] has out-of-range {field_name}"
        )
    return parsed


def _optional_int(
    record: _GeneratedMessage,
    field_name: str,
    record_name: str,
) -> Optional[int]:
    """Return one optional signed integer field."""
    value = _optional_scalar(record, field_name, record_name)
    if not value:
        return None
    try:
        return int(value, 10)
    except ValueError as error:
        raise RuntimeError(
            f"plan.{record_name}[] has non-integer {field_name}"
        ) from error
