"""Unit tests for feature engineering pipeline and extractors."""

from __future__ import annotations

from datetime import datetime, timezone, UTC

from src.features import (
    EntityStateTracker,
    FeaturePipeline,
    FeatureVector,
    extract_flow_features,
    extract_temporal_features,
)
from src.ingestion.models import SecurityEvent


class TestFeatureExtractors:
    def test_extract_temporal_features(self) -> None:
        # Wednesday 14:30 UTC
        dt = datetime(2026, 8, 26, 14, 30, 0, tzinfo=UTC)
        res = extract_temporal_features(dt)
        assert res["hour_of_day"] == 14
        assert res["day_of_week"] == 2  # Wednesday
        assert res["is_weekend"] is False
        assert res["is_off_hours"] is False

        # Sunday 22:00 UTC (weekend + off hours)
        dt_weekend = datetime(2026, 8, 30, 22, 0, 0, tzinfo=UTC)
        res_w = extract_temporal_features(dt_weekend)
        assert res_w["hour_of_day"] == 22
        assert res_w["day_of_week"] == 6
        assert res_w["is_weekend"] is True
        assert res_w["is_off_hours"] is True

    def test_extract_flow_features(self) -> None:
        event = SecurityEvent(
            timestamp=datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC),
            bytes_sent=1000,
            bytes_received=4000,
            duration=2.0,
            source="test",
            raw_data={},
        )
        res = extract_flow_features(event)
        assert res["bytes_total"] == 5000.0
        assert res["bytes_per_sec"] == 2500.0
        assert 0.19 < res["bytes_ratio"] < 0.21

    def test_extract_flow_zero_duration(self) -> None:
        event = SecurityEvent(
            timestamp=datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC),
            bytes_sent=500,
            bytes_received=0,
            duration=0.0,
            source="test",
            raw_data={},
        )
        res = extract_flow_features(event)
        assert res["bytes_per_sec"] == 0.0


class TestEntityStateTracker:
    def test_rolling_window_counts(self) -> None:
        tracker = EntityStateTracker(max_history_sec=900.0)

        # Event 1 at t=0
        e1 = SecurityEvent(
            timestamp=datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC),
            source_ip="192.168.1.50",
            destination_ip="10.0.0.1",
            destination_port=80,
            source="test",
            raw_data={},
        )
        s1 = tracker.record_and_get_stats(e1)
        assert s1["conns_1m"] == 1
        assert s1["conns_5m"] == 1
        assert s1["unique_dst_ips_5m"] == 1
        assert s1["unique_dst_ports_5m"] == 1

        # Event 2 at t=10s, different port & IP
        e2 = SecurityEvent(
            timestamp=datetime(2026, 8, 28, 12, 0, 10, tzinfo=UTC),
            source_ip="192.168.1.50",
            destination_ip="10.0.0.2",
            destination_port=443,
            source="test",
            raw_data={},
        )
        s2 = tracker.record_and_get_stats(e2)
        assert s2["conns_1m"] == 2
        assert s2["unique_dst_ips_5m"] == 2
        assert s2["unique_dst_ports_5m"] == 2

    def test_auth_burst_detection(self) -> None:
        tracker = EntityStateTracker()

        # Send 6 rapid failed auth events
        for i in range(6):
            e = SecurityEvent(
                timestamp=datetime(2026, 8, 28, 12, 0, i * 2, tzinfo=UTC),
                source_ip="10.10.10.10",
                username=f"user_{i}",
                event_type="authentication",
                action="failed",
                status="failure",
                source="test",
                raw_data={},
            )
            stats = tracker.record_and_get_stats(e)

        assert stats["auth_failed_1m"] == 6
        assert stats["auth_failure_burst"] is True
        assert stats["unique_users_targeted_5m"] == 6
        assert stats["auth_fail_ratio_5m"] == 1.0


class TestFeaturePipeline:
    def test_pipeline_process_event(self) -> None:
        pipeline = FeaturePipeline()
        event = SecurityEvent(
            timestamp=datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC),
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            destination_port=80,
            bytes_sent=150,
            bytes_received=600,
            duration=0.5,
            source="test",
            raw_data={},
        )
        fv = pipeline.process_event(event)

        assert isinstance(fv, FeatureVector)
        assert fv.entity_id == "192.168.1.1"
        assert fv.hour_of_day == 12
        assert fv.bytes_sent == 150.0
        assert fv.conns_1m == 1

        num_dict = fv.to_numeric_dict()
        assert "hour_of_day" in num_dict
        assert "auth_failed_1m" in num_dict

        vec = fv.to_vector(["hour_of_day", "conns_1m", "bytes_sent"])
        assert vec == [12.0, 1.0, 150.0]

    def test_pipeline_dataset_generation(self) -> None:
        pipeline = FeaturePipeline()
        events = [
            SecurityEvent(
                timestamp=datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC),
                source_ip="192.168.1.1",
                bytes_sent=100,
                source="test",
                raw_data={},
            ),
            SecurityEvent(
                timestamp=datetime(2026, 8, 28, 12, 0, 5, tzinfo=UTC),
                source_ip="192.168.1.1",
                bytes_sent=200,
                source="test",
                raw_data={},
            ),
        ]
        data = pipeline.to_dataframe(events)
        assert len(data) == 2
