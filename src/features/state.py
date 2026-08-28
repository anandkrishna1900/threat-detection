"""Entity state and sliding window tracker for real-time feature computation."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from src.ingestion.models import SecurityEvent


@dataclass
class WindowRecord:
    """Individual lightweight record saved inside sliding windows."""

    timestamp: float  # POSIX timestamp in seconds
    destination_ip: str | None
    destination_port: int | None
    bytes_sent: int
    bytes_received: int
    is_auth_failed: bool
    is_auth_success: bool
    username: str | None


@dataclass
class EntityHistory:
    """Sliding history buffer for a single entity (e.g. IP or username)."""

    events: deque[WindowRecord] = field(default_factory=deque)
    last_seen_ts: float | None = None

    def prune(self, current_ts: float, max_window_sec: float = 900.0) -> None:
        """Remove events older than max_window_sec from the deque."""
        cutoff = current_ts - max_window_sec
        while self.events and self.events[0].timestamp < cutoff:
            self.events.popleft()


class EntityStateTracker:
    """Maintains sliding-window behavioral state for entities (IPs, users, hosts)."""

    def __init__(self, max_history_sec: float = 900.0) -> None:
        self.max_history_sec = max_history_sec
        self.entities: dict[str, EntityHistory] = defaultdict(EntityHistory)

    def _get_entity_key(self, event: SecurityEvent) -> str:
        """Determine primary entity identifier."""
        return event.source_ip or event.username or event.hostname or "unknown"

    def record_and_get_stats(self, event: SecurityEvent) -> dict[str, Any]:
        """
        Record a new event for an entity and return temporal window statistics.
        """
        entity_key = self._get_entity_key(event)
        history = self.entities[entity_key]

        event_ts = event.timestamp.timestamp()
        history.prune(event_ts, max_window_sec=self.max_history_sec)

        time_since_last = (
            (event_ts - history.last_seen_ts)
            if history.last_seen_ts is not None
            else 0.0
        )
        history.last_seen_ts = event_ts

        # Determine authentication flags
        is_auth_failed = False
        is_auth_success = False
        if event.event_type == "authentication" or event.action in (
            "login",
            "auth",
            "authenticate",
            "failed",
            "success",
        ):
            if event.action == "failed" or event.status in (
                "failed",
                "failure",
                "FAILURE",
                "error",
            ):
                is_auth_failed = True
            elif event.action == "success" or event.status in (
                "success",
                "SUCCESS",
                "ok",
            ):
                is_auth_success = True

        rec = WindowRecord(
            timestamp=event_ts,
            destination_ip=event.destination_ip,
            destination_port=event.destination_port,
            bytes_sent=event.bytes_sent or 0,
            bytes_received=event.bytes_received or 0,
            is_auth_failed=is_auth_failed,
            is_auth_success=is_auth_success,
            username=event.username,
        )
        history.events.append(rec)

        # Compute window aggregations: 1m (60s), 5m (300s), 15m (900s)
        cutoff_1m = event_ts - 60.0
        cutoff_5m = event_ts - 300.0

        conns_1m = 0
        conns_5m = 0
        conns_15m = len(history.events)

        auth_failed_1m = 0
        auth_failed_5m = 0
        auth_success_5m = 0

        unique_dst_ips_5m: set[str] = set()
        unique_dst_ports_5m: set[int] = set()
        unique_users_5m: set[str] = set()

        bytes_sent_5m = 0.0
        bytes_recv_5m = 0.0

        for r in history.events:
            # 15m is entire deque (already pruned to 900s)
            if r.timestamp >= cutoff_5m:
                conns_5m += 1
                if r.destination_ip:
                    unique_dst_ips_5m.add(r.destination_ip)
                if r.destination_port is not None:
                    unique_dst_ports_5m.add(r.destination_port)
                if r.username:
                    unique_users_5m.add(r.username)
                if r.is_auth_failed:
                    auth_failed_5m += 1
                if r.is_auth_success:
                    auth_success_5m += 1
                bytes_sent_5m += r.bytes_sent
                bytes_recv_5m += r.bytes_received

                if r.timestamp >= cutoff_1m:
                    conns_1m += 1
                    if r.is_auth_failed:
                        auth_failed_1m += 1

        total_auth_5m = auth_failed_5m + auth_success_5m
        auth_fail_ratio_5m = (
            (auth_failed_5m / total_auth_5m) if total_auth_5m > 0 else 0.0
        )

        return {
            "entity_id": entity_key,
            "time_since_last_event_sec": max(0.0, time_since_last),
            "conns_1m": conns_1m,
            "conns_5m": conns_5m,
            "conns_15m": conns_15m,
            "events_1m": conns_1m,
            "events_5m": conns_5m,
            "events_15m": conns_15m,
            "unique_dst_ips_5m": len(unique_dst_ips_5m),
            "unique_dst_ports_5m": len(unique_dst_ports_5m),
            "unique_users_targeted_5m": len(unique_users_5m),
            "bytes_sent_5m": bytes_sent_5m,
            "bytes_recv_5m": bytes_recv_5m,
            "auth_failed_1m": auth_failed_1m,
            "auth_failed_5m": auth_failed_5m,
            "auth_success_5m": auth_success_5m,
            "auth_fail_ratio_5m": auth_fail_ratio_5m,
            "auth_failure_burst": auth_failed_1m >= 5,
        }

    def reset(self) -> None:
        """Reset all tracked entity history."""
        self.entities.clear()
