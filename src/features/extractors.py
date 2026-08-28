"""Feature extractors for temporal, flow, and event metrics."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from src.ingestion.models import SecurityEvent


def extract_temporal_features(ts: datetime) -> dict[str, Any]:
    """Extract temporal calendar features from UTC datetime."""
    hour = ts.hour
    day_of_week = ts.weekday()  # 0 = Monday, 6 = Sunday
    is_weekend = day_of_week >= 5
    # Off-hours: before 8 AM or after 6 PM (18:00) UTC
    is_off_hours = hour < 8 or hour >= 18

    return {
        "hour_of_day": hour,
        "day_of_week": day_of_week,
        "is_weekend": is_weekend,
        "is_off_hours": is_off_hours,
    }


def extract_flow_features(event: SecurityEvent) -> dict[str, float]:
    """Extract flow byte rates and duration ratios."""
    bytes_sent = float(event.bytes_sent or 0)
    bytes_recv = float(event.bytes_received or 0)
    bytes_total = bytes_sent + bytes_recv
    duration = float(event.duration or 0.0)

    bytes_per_sec = (bytes_total / duration) if duration > 0 else 0.0
    bytes_ratio = (bytes_sent / (bytes_total + 1e-5))

    return {
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_recv,
        "bytes_total": bytes_total,
        "duration": duration,
        "bytes_per_sec": bytes_per_sec,
        "bytes_ratio": bytes_ratio,
    }
