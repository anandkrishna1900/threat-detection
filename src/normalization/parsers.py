"""Value normalization parsers for timestamps, IPs, ports, and protocols."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

# Standard protocol number to name mapping (IANA)
PROTOCOL_NUMBER_MAP: dict[int, str] = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "IPv6-ICMP",
    89: "OSPF",
}

COMMON_DATETIME_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M:%S.%f",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%d/%b/%Y:%H:%M:%S %z",
    "%Y/%m/%d %H:%M:%S",
]

NULL_STRINGS = {"", "null", "none", "nan", "-", "nil", "n/a", "unknown"}


def is_null_value(val: Any) -> bool:
    """Check if value represents an explicit missing/null value."""
    if val is None:
        return True
    if isinstance(val, str) and val.strip().lower() in NULL_STRINGS:
        return True
    return False


def normalize_timestamp(val: Any) -> datetime | None:
    """
    Parse a timestamp into a timezone-aware UTC datetime.
    Supports ISO formats, UNIX epochs (sec/msec/microsec), and standard date strings.
    """
    if is_null_value(val):
        return None

    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val.astimezone(timezone.utc)

    # Numeric UNIX timestamp
    if isinstance(val, (int, float)):
        # Check if timestamp is in milliseconds or microseconds
        if val > 1e14:  # microseconds
            val = val / 1e6
        elif val > 1e11:  # milliseconds
            val = val / 1e3
        return datetime.fromtimestamp(val, tz=timezone.utc)

    val_str = str(val).strip()
    if is_null_value(val_str):
        return None

    # Check numeric epoch in string format
    if re.match(r"^\d+(\.\d+)?$", val_str):
        try:
            num_val = float(val_str)
            if num_val > 1e14:
                num_val /= 1e6
            elif num_val > 1e11:
                num_val /= 1e3
            return datetime.fromtimestamp(num_val, tz=timezone.utc)
        except (ValueError, OverflowError):
            pass

    # Try ISO 8601
    try:
        # Handle trailing Z
        iso_str = val_str.replace("Z", "+00:00") if val_str.endswith("Z") else val_str
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass

    # Try common formats
    for fmt in COMMON_DATETIME_FORMATS:
        try:
            dt = datetime.strptime(val_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue

    return None


def normalize_ip(val: Any) -> str | None:
    """Validate and clean IP address (IPv4 or IPv6)."""
    if is_null_value(val):
        return None

    ip_str = str(val).strip()
    # Strip port suffix if attached like "192.168.1.1:8080"
    if ":" in ip_str and ip_str.count(":") == 1 and "." in ip_str:
        ip_str = ip_str.split(":")[0]

    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return str(ip_obj)
    except ValueError:
        return None


def normalize_port(val: Any) -> int | None:
    """Validate and normalize TCP/UDP port number (0-65535)."""
    if is_null_value(val):
        return None

    try:
        port_int = int(float(str(val).strip()))
        if 0 <= port_int <= 65535:
            return port_int
    except (ValueError, TypeError):
        pass
    return None


def normalize_protocol(val: Any) -> str | None:
    """Standardize protocol representation (e.g. 6 -> TCP, 'udp' -> UDP)."""
    if is_null_value(val):
        return None

    # Check numeric protocol code
    try:
        proto_num = int(val)
        if proto_num in PROTOCOL_NUMBER_MAP:
            return PROTOCOL_NUMBER_MAP[proto_num]
    except (ValueError, TypeError):
        pass

    proto_str = str(val).strip().upper()
    return proto_str if proto_str else None


def normalize_int(val: Any) -> int | None:
    """Parse integer or return None for missing/invalid data."""
    if is_null_value(val):
        return None
    try:
        num = int(float(str(val).strip()))
        return num if num >= 0 else None
    except (ValueError, TypeError):
        return None


def normalize_float(val: Any) -> float | None:
    """Parse float or return None for missing/invalid data."""
    if is_null_value(val):
        return None
    try:
        num = float(str(val).strip())
        return num if num >= 0 else None
    except (ValueError, TypeError):
        return None


def normalize_string(val: Any) -> str | None:
    """Trim string or return None if empty/null."""
    if is_null_value(val):
        return None
    s = str(val).strip()
    return s if s and s.lower() not in NULL_STRINGS else None
