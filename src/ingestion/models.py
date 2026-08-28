"""Data models for normalized security events."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SecurityEvent(BaseModel):
    """Canonical security event schema."""

    model_config = ConfigDict(extra="ignore")

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
    bytes_sent: int | None = Field(default=None, ge=0)
    bytes_received: int | None = Field(default=None, ge=0)
    duration: float | None = Field(default=None, ge=0)
    username: str | None = None
    hostname: str | None = None
    event_type: str | None = None
    action: str | None = None
    status: str | None = None
    source: str
    raw_data: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("protocol", mode="before")
    @classmethod
    def _normalize_protocol(cls, v: object) -> str | None:
        if v is None:
            return None
        return str(v).upper()

    @field_validator("timestamp", mode="before")
    @classmethod
    def _parse_timestamp(cls, v: object) -> datetime:
        if isinstance(v, datetime):
            return v
        try:
            return datetime.fromisoformat(str(v))
        except ValueError as exc:
            raise ValueError(f"Cannot parse timestamp: {v!r}") from exc
