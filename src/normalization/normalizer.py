"""Event normalization engine converting raw logs/records into canonical SecurityEvents."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from typing import Any

from src.common.logging_setup import get_logger
from src.ingestion.models import SecurityEvent
from src.normalization.field_mappings import DEFAULT_FIELD_ALIASES, PROFILES, MappingProfile
from src.normalization.parsers import (
    normalize_float,
    normalize_int,
    normalize_ip,
    normalize_port,
    normalize_protocol,
    normalize_string,
    normalize_timestamp,
)

logger = get_logger(__name__)


class EventNormalizer:
    """Normalizes heterogeneous event records into validated SecurityEvents."""

    def __init__(
        self, profile_name: str | None = None, custom_aliases: dict[str, list[str]] | None = None
    ) -> None:
        self.profile: MappingProfile | None = PROFILES.get(profile_name) if profile_name else None
        self.aliases = {**DEFAULT_FIELD_ALIASES, **(custom_aliases or {})}
        # Invert aliases for fast lookup: alias_lower -> canonical_field
        self._alias_lookup: dict[str, str] = {}
        for canonical_name, alias_list in self.aliases.items():
            for alias in alias_list:
                self._alias_lookup[alias.lower().strip()] = canonical_name

    def _extract_field(self, raw_record: dict[str, Any], canonical_field: str) -> Any:
        """Extract value for a canonical field using profile or dynamic aliases."""
        # 1. Check profile explicit mapping
        if self.profile and self.profile.field_map:
            for raw_key, target in self.profile.field_map.items():
                if target == canonical_field and raw_key in raw_record:
                    return raw_record[raw_key]

        # 2. Check exact canonical match
        if canonical_field in raw_record:
            return raw_record[canonical_field]

        # 3. Check alias list
        if canonical_field in self.aliases:
            for alias in self.aliases[canonical_field]:
                if alias in raw_record:
                    return raw_record[alias]
                # Case-insensitive check
                alias_lower = alias.lower()
                for k, v in raw_record.items():
                    if k.lower().strip() == alias_lower:
                        return v

        return None

    def normalize(self, raw_record: dict[str, Any], source: str = "unknown") -> SecurityEvent:
        """Convert a raw dictionary record into a canonical SecurityEvent."""
        raw_ts = self._extract_field(raw_record, "timestamp")
        parsed_ts = normalize_timestamp(raw_ts)

        metadata: dict[str, Any] = {}
        if parsed_ts is None:
            parsed_ts = datetime.now(timezone.utc)
            metadata["timestamp_generated"] = True
            if raw_ts is not None:
                metadata["raw_timestamp_unparsed"] = str(raw_ts)

        # Normalize components
        src_ip = normalize_ip(self._extract_field(raw_record, "source_ip"))
        dst_ip = normalize_ip(self._extract_field(raw_record, "destination_ip"))
        src_port = normalize_port(self._extract_field(raw_record, "source_port"))
        dst_port = normalize_port(self._extract_field(raw_record, "destination_port"))
        protocol = normalize_protocol(self._extract_field(raw_record, "protocol"))
        bytes_sent = normalize_int(self._extract_field(raw_record, "bytes_sent"))
        bytes_recv = normalize_int(self._extract_field(raw_record, "bytes_received"))
        duration = normalize_float(self._extract_field(raw_record, "duration"))
        username = normalize_string(self._extract_field(raw_record, "username"))
        hostname = normalize_string(self._extract_field(raw_record, "hostname"))
        event_type = normalize_string(self._extract_field(raw_record, "event_type"))
        action = normalize_string(self._extract_field(raw_record, "action"))
        status = normalize_string(self._extract_field(raw_record, "status"))

        # Preserve extra metadata if present in profile or raw record
        for k, v in raw_record.items():
            if k.lower() in ("label", "attack", "tag"):
                metadata[k.lower()] = v

        return SecurityEvent(
            timestamp=parsed_ts,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            protocol=protocol,
            bytes_sent=bytes_sent,
            bytes_received=bytes_recv,
            duration=duration,
            username=username,
            hostname=hostname,
            event_type=event_type,
            action=action,
            status=status,
            source=source,
            raw_data=raw_record,
            metadata=metadata,
        )

    def normalize_stream(
        self, records: Iterable[dict[str, Any]], source: str = "unknown"
    ) -> Iterator[SecurityEvent]:
        """Stream normalized SecurityEvents from an iterable of raw records."""
        for record in records:
            if isinstance(record, dict):
                yield self.normalize(record, source=source)
