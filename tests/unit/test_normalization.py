"""Unit tests for event normalization layer."""

from __future__ import annotations

from datetime import datetime, timezone, UTC

from src.normalization import (
    EventNormalizer,
    normalize_float,
    normalize_int,
    normalize_ip,
    normalize_port,
    normalize_protocol,
    normalize_timestamp,
)


class TestParsers:
    def test_normalize_timestamp_iso(self) -> None:
        dt = normalize_timestamp("2026-08-28T12:00:00Z")
        assert dt == datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC)

        dt_offset = normalize_timestamp("2026-08-28T14:00:00+02:00")
        assert dt_offset == datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC)

    def test_normalize_timestamp_epoch(self) -> None:
        # Seconds
        dt = normalize_timestamp(1787918400)
        assert dt is not None
        assert dt.tzinfo == UTC

        # Milliseconds
        dt_ms = normalize_timestamp(1787918400000)
        assert dt_ms is not None
        assert dt_ms.tzinfo == UTC

    def test_normalize_timestamp_formats(self) -> None:
        dt = normalize_timestamp("2026-08-28 12:00:00")
        assert dt == datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC)

        dt_euro = normalize_timestamp("28/08/2026 12:00:00")
        assert dt_euro == datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC)

    def test_normalize_timestamp_nulls(self) -> None:
        assert normalize_timestamp(None) is None
        assert normalize_timestamp("-") is None
        assert normalize_timestamp("NaN") is None
        assert normalize_timestamp("unknown") is None

    def test_normalize_ip(self) -> None:
        assert normalize_ip("192.168.1.1") == "192.168.1.1"
        assert normalize_ip("10.0.0.1:8080") == "10.0.0.1"
        assert normalize_ip("::1") == "::1"
        assert normalize_ip("invalid_ip") is None
        assert normalize_ip("-") is None
        assert normalize_ip(None) is None

    def test_normalize_port(self) -> None:
        assert normalize_port(80) == 80
        assert normalize_port("443") == 443
        assert normalize_port(0) == 0
        assert normalize_port(65535) == 65535
        assert normalize_port(70000) is None
        assert normalize_port(-1) is None
        assert normalize_port("-") is None
        assert normalize_port(None) is None

    def test_normalize_protocol(self) -> None:
        assert normalize_protocol(6) == "TCP"
        assert normalize_protocol(17) == "UDP"
        assert normalize_protocol(1) == "ICMP"
        assert normalize_protocol("tcp") == "TCP"
        assert normalize_protocol("UDP") == "UDP"
        assert normalize_protocol("-") is None
        assert normalize_protocol(None) is None

    def test_normalize_numeric(self) -> None:
        assert normalize_int("100") == 100
        assert normalize_int("-5") is None
        assert normalize_int("NaN") is None
        assert normalize_float("12.34") == 12.34
        assert normalize_float("-1.5") is None


class TestEventNormalizer:
    def test_normalize_generic_aliases(self) -> None:
        normalizer = EventNormalizer()
        raw = {
            "time": "2026-08-28T12:00:00Z",
            "src_ip": "192.168.1.10",
            "dst_ip": "10.0.0.1",
            "sport": "50000",
            "dsport": "80",
            "proto": "tcp",
            "sbytes": "1200",
            "dbytes": "45000",
            "dur": "1.5",
            "user": "alice",
        }
        event = normalizer.normalize(raw, source="test_feed")

        assert event.source_ip == "192.168.1.10"
        assert event.destination_ip == "10.0.0.1"
        assert event.source_port == 50000
        assert event.destination_port == 80
        assert event.protocol == "TCP"
        assert event.bytes_sent == 1200
        assert event.bytes_received == 45000
        assert event.duration == 1.5
        assert event.username == "alice"
        assert event.source == "test_feed"
        assert event.raw_data == raw

    def test_normalize_cic_ids_profile(self) -> None:
        normalizer = EventNormalizer(profile_name="cic_ids")
        raw = {
            "Timestamp": "2026-08-28 12:00:00",
            "Source IP": "192.168.1.50",
            "Destination IP": "8.8.8.8",
            "Source Port": 5353,
            "Destination Port": 53,
            "Protocol": 17,
            "Flow Duration": 250.0,
            "Total Length of Fwd Packets": 128,
            "Total Length of Bwd Packets": 512,
            "Label": "BENIGN",
        }
        event = normalizer.normalize(raw, source="cic_ids_test")

        assert event.source_ip == "192.168.1.50"
        assert event.destination_ip == "8.8.8.8"
        assert event.source_port == 5353
        assert event.destination_port == 53
        assert event.protocol == "UDP"
        assert event.duration == 250.0
        assert event.bytes_sent == 128
        assert event.bytes_received == 512
        assert event.metadata.get("label") == "BENIGN"

    def test_normalize_unsw_nb15_profile(self) -> None:
        normalizer = EventNormalizer(profile_name="unsw_nb15")
        raw = {
            "srcip": "172.16.0.5",
            "dstip": "172.16.0.1",
            "sport": 1234,
            "dsport": 80,
            "proto": "tcp",
            "dur": 0.05,
            "sbytes": 500,
            "dbytes": 1000,
            "state": "FIN",
            "attack_cat": "Generic",
        }
        event = normalizer.normalize(raw, source="unsw_test")

        assert event.source_ip == "172.16.0.5"
        assert event.destination_ip == "172.16.0.1"
        assert event.source_port == 1234
        assert event.destination_port == 80
        assert event.protocol == "TCP"
        assert event.duration == 0.05
        assert event.status == "FIN"
        assert event.event_type == "Generic"

    def test_normalize_stream(self) -> None:
        normalizer = EventNormalizer()
        raw_list = [
            {"time": "2026-08-28T12:00:00Z", "src_ip": "1.1.1.1"},
            {"time": "2026-08-28T12:00:01Z", "src_ip": "2.2.2.2"},
        ]
        events = list(normalizer.normalize_stream(raw_list, source="stream_test"))

        assert len(events) == 2
        assert events[0].source_ip == "1.1.1.1"
        assert events[1].source_ip == "2.2.2.2"
