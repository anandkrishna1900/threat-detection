"""Feature vector data models for threat detection engines."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class FeatureVector(BaseModel):
    """
    Extracted feature vector for a SecurityEvent at time t.
    All features are purely numerical/boolean and leak no attack labels.
    """

    model_config = ConfigDict(extra="ignore")

    event_id: str
    timestamp: datetime
    entity_id: str  # Primary entity (e.g., source_ip or username)

    # --- Temporal Features ---
    hour_of_day: int = Field(ge=0, le=23)
    day_of_week: int = Field(ge=0, le=6)
    is_weekend: bool
    is_off_hours: bool  # e.g., before 08:00 or after 18:00

    # --- Network Flow Features ---
    bytes_sent: float = 0.0
    bytes_received: float = 0.0
    bytes_total: float = 0.0
    duration: float = 0.0
    bytes_per_sec: float = 0.0
    bytes_ratio: float = 0.0  # bytes_sent / (bytes_sent + bytes_received + 1e-5)

    # --- Network Window Features (1m / 5m / 15m) ---
    conns_1m: int = 0
    conns_5m: int = 0
    conns_15m: int = 0
    unique_dst_ips_5m: int = 0
    unique_dst_ports_5m: int = 0
    bytes_sent_5m: float = 0.0
    bytes_recv_5m: float = 0.0

    # --- Authentication Features ---
    auth_failed_1m: int = 0
    auth_failed_5m: int = 0
    auth_success_5m: int = 0
    auth_fail_ratio_5m: float = 0.0  # failed / (failed + success + 1e-5)
    unique_users_targeted_5m: int = 0
    time_since_last_event_sec: float = 0.0
    auth_failure_burst: bool = False  # True if >= 5 failed logins within 60s

    # --- Host & Event Frequency Features ---
    events_1m: int = 0
    events_5m: int = 0
    events_15m: int = 0

    # Context / debug metadata
    feature_dict_cache: dict[str, float] | None = None

    def to_numeric_dict(self) -> dict[str, float]:
        """Convert all analytical features to a pure float dictionary for ML/scoring."""
        return {
            "hour_of_day": float(self.hour_of_day),
            "day_of_week": float(self.day_of_week),
            "is_weekend": 1.0 if self.is_weekend else 0.0,
            "is_off_hours": 1.0 if self.is_off_hours else 0.0,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "bytes_total": self.bytes_total,
            "duration": self.duration,
            "bytes_per_sec": self.bytes_per_sec,
            "bytes_ratio": self.bytes_ratio,
            "conns_1m": float(self.conns_1m),
            "conns_5m": float(self.conns_5m),
            "conns_15m": float(self.conns_15m),
            "unique_dst_ips_5m": float(self.unique_dst_ips_5m),
            "unique_dst_ports_5m": float(self.unique_dst_ports_5m),
            "bytes_sent_5m": self.bytes_sent_5m,
            "bytes_recv_5m": self.bytes_recv_5m,
            "auth_failed_1m": float(self.auth_failed_1m),
            "auth_failed_5m": float(self.auth_failed_5m),
            "auth_success_5m": float(self.auth_success_5m),
            "auth_fail_ratio_5m": self.auth_fail_ratio_5m,
            "unique_users_targeted_5m": float(self.unique_users_targeted_5m),
            "time_since_last_event_sec": self.time_since_last_event_sec,
            "auth_failure_burst": 1.0 if self.auth_failure_burst else 0.0,
            "events_1m": float(self.events_1m),
            "events_5m": float(self.events_5m),
            "events_15m": float(self.events_15m),
        }

    def to_vector(self, feature_names: list[str] | None = None) -> list[float]:
        """Return ordered numeric feature values list."""
        num_dict = self.to_numeric_dict()
        if feature_names is None:
            return list(num_dict.values())
        return [num_dict.get(name, 0.0) for name in feature_names]
