"""Unit tests for the data ingestion layer."""

from __future__ import annotations

import json
from datetime import datetime, timezone, UTC
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.ingestion import (
    CSVSource,
    JSONLinesSource,
    JSONSource,
    SecurityEvent,
    SyntheticSource,
)
from src.ingestion.base import IngestionStats


class TestSecurityEventModel:
    def test_security_event_defaults_and_nullables(self) -> None:
        event = SecurityEvent(
            timestamp=datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC),
            source="csv:test.csv",
            raw_data={"test": 123},
        )
        assert event.source_ip is None
        assert event.destination_port is None
        assert event.protocol is None
        assert event.username is None
        assert event.raw_data == {"test": 123}
        assert event.event_id is not None

    def test_security_event_protocol_normalization(self) -> None:
        event = SecurityEvent(
            timestamp="2026-08-28T12:00:00Z",
            protocol="tcp",
            source="csv:test.csv",
            raw_data={},
        )
        assert event.protocol == "TCP"

    def test_security_event_invalid_timestamp_raises(self) -> None:
        with pytest.raises(ValidationError):
            SecurityEvent(
                timestamp="invalid-timestamp",
                source="test",
                raw_data={},
            )


class TestCSVSource:
    def test_csv_read_valid(self, tmp_path: Path) -> None:
        csv_file = tmp_path / "events.csv"
        csv_file.write_text(
            "timestamp,source_ip,destination_port\n"
            "2026-08-28T12:00:00Z,192.168.1.1,80\n"
            "2026-08-28T12:00:01Z,192.168.1.2,443\n",
            encoding="utf-8",
        )

        source = CSVSource(csv_file)
        records = list(source.read())

        assert len(records) == 2
        assert records[0]["source_ip"] == "192.168.1.1"
        assert records[1]["destination_port"] == "443"

        stats = source.get_stats()
        assert stats.records_read == 2
        assert stats.records_yielded == 2
        assert stats.records_skipped == 0

    def test_csv_skip_blank_rows(self, tmp_path: Path) -> None:
        csv_file = tmp_path / "events_with_blanks.csv"
        csv_file.write_text(
            "timestamp,source_ip\n"
            "2026-08-28T12:00:00Z,192.168.1.1\n"
            "\n"
            "2026-08-28T12:00:02Z,192.168.1.3\n",
            encoding="utf-8",
        )

        source = CSVSource(csv_file)
        records = list(source.read())

        assert len(records) == 2
        stats = source.get_stats()
        assert stats.records_read == 3
        assert stats.records_yielded == 2
        assert stats.records_skipped == 1

    def test_csv_missing_file_raises(self, tmp_path: Path) -> None:
        source = CSVSource(tmp_path / "non_existent.csv")
        with pytest.raises(FileNotFoundError):
            list(source.read())


class TestJSONSource:
    def test_json_array_reading(self, tmp_path: Path) -> None:
        json_file = tmp_path / "events.json"
        data = [
            {"timestamp": "2026-08-28T12:00:00Z", "source_ip": "1.1.1.1"},
            {"timestamp": "2026-08-28T12:00:01Z", "source_ip": "2.2.2.2"},
            "invalid_non_dict_element",
        ]
        json_file.write_text(json.dumps(data), encoding="utf-8")

        source = JSONSource(json_file)
        records = list(source.read())

        assert len(records) == 2
        stats = source.get_stats()
        assert stats.records_read == 3
        assert stats.records_yielded == 2
        assert stats.records_skipped == 1

    def test_json_single_object_reading(self, tmp_path: Path) -> None:
        json_file = tmp_path / "single_event.json"
        data = {"timestamp": "2026-08-28T12:00:00Z", "source_ip": "1.1.1.1"}
        json_file.write_text(json.dumps(data), encoding="utf-8")

        source = JSONSource(json_file)
        records = list(source.read())

        assert len(records) == 1
        assert records[0]["source_ip"] == "1.1.1.1"
        stats = source.get_stats()
        assert stats.records_read == 1
        assert stats.records_yielded == 1

    def test_json_invalid_file(self, tmp_path: Path) -> None:
        json_file = tmp_path / "corrupt.json"
        json_file.write_text("invalid json content", encoding="utf-8")

        source = JSONSource(json_file)
        records = list(source.read())

        assert len(records) == 0
        stats = source.get_stats()
        assert stats.records_skipped == 1


class TestJSONLinesSource:
    def test_jsonl_reading(self, tmp_path: Path) -> None:
        jsonl_file = tmp_path / "events.jsonl"
        lines = [
            json.dumps({"timestamp": "2026-08-28T12:00:00Z", "source_ip": "10.0.0.1"}),
            "corrupted line { not json",
            json.dumps({"timestamp": "2026-08-28T12:00:02Z", "source_ip": "10.0.0.2"}),
        ]
        jsonl_file.write_text("\n".join(lines), encoding="utf-8")

        source = JSONLinesSource(jsonl_file)
        records = list(source.read())

        assert len(records) == 2
        stats = source.get_stats()
        assert stats.records_read == 3
        assert stats.records_yielded == 2
        assert stats.records_skipped == 1


class TestSyntheticSource:
    def test_synthetic_source_stream(self) -> None:
        raw_items = [
            {"timestamp": "2026-08-28T12:00:00Z", "action": "allow"},
            12345,  # non-dict item
            {"timestamp": "2026-08-28T12:00:01Z", "action": "block"},
        ]
        source = SyntheticSource(raw_items)
        records = list(source.read())

        assert len(records) == 2
        assert records[0]["action"] == "allow"
        assert records[1]["action"] == "block"

        stats = source.get_stats()
        assert stats.records_read == 3
        assert stats.records_yielded == 2
        assert stats.records_skipped == 1


class TestIngestionStats:
    def test_stats_tracking(self) -> None:
        stats = IngestionStats()
        stats.record_success()
        stats.record_failure("raw_data", "parse error")

        assert stats.records_read == 2
        assert stats.records_yielded == 1
        assert stats.records_skipped == 1
        assert len(stats.errors) == 1
        assert stats.errors[0]["reason"] == "parse error"
