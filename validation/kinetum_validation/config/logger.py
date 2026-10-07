"""Emit bounded readable diagnostics without changing platform records."""

from __future__ import annotations

import os
import socket
import sys
import threading
from datetime import datetime, timezone


_APPLICATION = "kinetum_validation"
_HOSTNAME = socket.gethostname()
_OUTPUT_LOCK = threading.Lock()
_MESSAGE_BYTES = 8192


def _timestamp() -> str:
    """Return emitter UTC in RFC 3339 form with six fractional digits."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond:06d}Z"


def set_log_application(application: str) -> None:
    """Select the fixed command role before its asynchronous work starts."""
    if application not in {"kinetum_validation", "kinetum_benchmark"}:
        raise ValueError("unknown harness logging application")
    global _APPLICATION  # pylint: disable=global-statement
    _APPLICATION = application


def _header(value: str, maximum: int) -> str:
    """Return a printable non-space header token or a dash for unavailable metadata."""
    if not value or len(value) > maximum or any(not 33 <= ord(char) <= 126 for char in value):
        return "-"
    return value


def _escape(value: bytes) -> str:
    """Encode controls, non-ASCII bytes, and escape markers unambiguously."""
    return "".join(
        "\\\\" if byte == 92 else
        f"\\x{byte:02x}" if byte < 32 or byte >= 127 else chr(byte)
        for byte in value
    )


def _emit(level: str, event: str, component: str, message: str) -> None:
    """Copy emitter facts and serialize one complete bounded record."""
    function = sys._getframe(2).f_code.co_name  # pylint: disable=protected-access
    raw_message = message[:_MESSAGE_BYTES + 1].encode("utf-8", errors="surrogatepass")
    raw_component = component[:49].encode("utf-8", errors="surrogatepass")
    raw_function = function[:129].encode("utf-8", errors="surrogatepass")
    truncated = (
        len(raw_message) > _MESSAGE_BYTES
        or len(raw_component) > 48 or len(raw_function) > 128
    )
    record = (
        f"{_timestamp()} [{level}] {_header(_HOSTNAME, 255)} "
        f"{_APPLICATION}[{os.getpid()}:{threading.get_native_id()}] {event} - "
        f"{_escape(raw_component[:48])}/{_escape(raw_function[:128])}: "
        f"{_escape(raw_message[:_MESSAGE_BYTES])}"
        + ("...[truncated]" if truncated else "") + "\n"
    )
    with _OUTPUT_LOCK:
        sys.stderr.write(record)
        sys.stderr.flush()


def log_info(component: str, message: str) -> None:
    """Emit an informational cold harness diagnostic."""
    _emit("INFO", "validation.info", component, message)


def log_warn(component: str, message: str) -> None:
    """Emit a warning without supplying severity for a foreign library."""
    _emit("WARN", "validation.warning", component, message)


def log_error(component: str, message: str) -> None:
    """Emit a failed harness operation as an error record."""
    _emit("ERROR", "validation.error", component, message)
