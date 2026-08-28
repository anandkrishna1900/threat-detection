"""Feature extraction pipeline coordinating stateful tracking and feature engineering."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

from src.features.extractors import extract_flow_features, extract_temporal_features
from src.features.models import FeatureVector
from src.features.state import EntityStateTracker
from src.ingestion.models import SecurityEvent


class FeaturePipeline:
    """Orchestrates temporal, behavioral, and sliding-window feature engineering."""

    def __init__(self, state_tracker: EntityStateTracker | None = None) -> None:
        self.state_tracker = state_tracker or EntityStateTracker()

    def process_event(self, event: SecurityEvent) -> FeatureVector:
        """Extract all features for a single SecurityEvent."""
        temporal_feats = extract_temporal_features(event.timestamp)
        flow_feats = extract_flow_features(event)
        window_stats = self.state_tracker.record_and_get_stats(event)

        return FeatureVector(
            event_id=event.event_id,
            timestamp=event.timestamp,
            entity_id=window_stats["entity_id"],
            hour_of_day=temporal_feats["hour_of_day"],
            day_of_week=temporal_feats["day_of_week"],
            is_weekend=temporal_feats["is_weekend"],
            is_off_hours=temporal_feats["is_off_hours"],
            bytes_sent=flow_feats["bytes_sent"],
            bytes_received=flow_feats["bytes_received"],
            bytes_total=flow_feats["bytes_total"],
            duration=flow_feats["duration"],
            bytes_per_sec=flow_feats["bytes_per_sec"],
            bytes_ratio=flow_feats["bytes_ratio"],
            conns_1m=window_stats["conns_1m"],
            conns_5m=window_stats["conns_5m"],
            conns_15m=window_stats["conns_15m"],
            events_1m=window_stats["events_1m"],
            events_5m=window_stats["events_5m"],
            events_15m=window_stats["events_15m"],
            unique_dst_ips_5m=window_stats["unique_dst_ips_5m"],
            unique_dst_ports_5m=window_stats["unique_dst_ports_5m"],
            bytes_sent_5m=window_stats["bytes_sent_5m"],
            bytes_recv_5m=window_stats["bytes_recv_5m"],
            auth_failed_1m=window_stats["auth_failed_1m"],
            auth_failed_5m=window_stats["auth_failed_5m"],
            auth_success_5m=window_stats["auth_success_5m"],
            auth_fail_ratio_5m=window_stats["auth_fail_ratio_5m"],
            unique_users_targeted_5m=window_stats["unique_users_targeted_5m"],
            time_since_last_event_sec=window_stats["time_since_last_event_sec"],
            auth_failure_burst=window_stats["auth_failure_burst"],
        )

    def process_stream(self, events: Iterable[SecurityEvent]) -> Iterator[FeatureVector]:
        """Stream FeatureVectors from a stream of SecurityEvents."""
        for event in events:
            yield self.process_event(event)

    def to_dataframe(self, events: Iterable[SecurityEvent]) -> Any:
        """Convert a collection of SecurityEvents into a tabular feature dataset."""
        rows: list[dict[str, Any]] = []
        for event in events:
            fv = self.process_event(event)
            row: dict[str, Any] = fv.to_numeric_dict()
            row["event_id"] = str(fv.event_id)
            row["entity_id"] = str(fv.entity_id)
            rows.append(row)

        try:
            import pandas as pd

            return pd.DataFrame(rows)
        except Exception:
            return rows

    def reset(self) -> None:
        """Reset entity tracking state."""
        self.state_tracker.reset()
