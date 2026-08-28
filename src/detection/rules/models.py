"""Data models for rule-based detection engine."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RuleSeverity(str, Enum):
    """Severity levels for detection rules."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RuleDefinition(BaseModel):
    """Schema for a configurable detection rule loaded from YAML."""

    model_config = ConfigDict(extra="ignore")

    id: str
    name: str
    description: str
    severity: RuleSeverity = RuleSeverity.MEDIUM
    enabled: bool = True
    mitre_tactic: str
    mitre_technique: str
    conditions: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)


class RuleMatch(BaseModel):
    """Output alert record produced when a detection rule triggers on an event."""

    model_config = ConfigDict(extra="ignore")

    rule_id: str
    rule_name: str
    severity: str
    confidence: float
    entity_id: str
    matched_event_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    mitre_tactic: str
    mitre_technique: str
    evidence: dict[str, Any] = Field(default_factory=dict)
