"""Unit tests for the rule-based detection engine."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from src.detection.rules import (
    RuleDefinition,
    RuleEngine,
    RuleMatch,
    RuleSeverity,
    load_rules_from_dict,
    load_rules_from_yaml,
)
from src.features.models import FeatureVector
from src.features.pipeline import FeaturePipeline
from src.ingestion.models import SecurityEvent


class TestRuleLoader:
    def test_load_default_yaml_rules(self) -> None:
        rules = load_rules_from_yaml()
        assert len(rules) == 10
        rule_ids = {r.id for r in rules}
        assert "RULE_AUTH_001" in rule_ids
        assert "RULE_NET_001" in rule_ids
        assert "RULE_HOST_001" in rule_ids

    def test_load_missing_file_returns_empty(self, tmp_path: Path) -> None:
        rules = load_rules_from_yaml(tmp_path / "non_existent.yaml")
        assert rules == []

    def test_load_from_dict(self) -> None:
        data = {
            "rules": [
                {
                    "id": "CUSTOM_001",
                    "name": "Custom Test Rule",
                    "description": "A test rule",
                    "severity": "HIGH",
                    "mitre_tactic": "Initial Access",
                    "mitre_technique": "T1190",
                    "conditions": {"auth_failed_count": 2},
                }
            ]
        }
        rules = load_rules_from_dict(data)
        assert len(rules) == 1
        assert rules[0].id == "CUSTOM_001"
        assert rules[0].severity == RuleSeverity.HIGH


class TestRuleEngineManagement:
    def test_engine_init_and_properties(self) -> None:
        engine = RuleEngine()
        assert len(engine.rules) == 10
        assert len(engine.active_rules) == 10

        # Disable a rule
        success = engine.disable_rule("RULE_AUTH_001")
        assert success is True
        assert len(engine.active_rules) == 9

        # Enable the rule back
        success = engine.enable_rule("RULE_AUTH_001")
        assert success is True
        assert len(engine.active_rules) == 10

    def test_get_non_existent_rule(self) -> None:
        engine = RuleEngine()
        assert engine.get_rule("NON_EXISTENT") is None
        assert engine.enable_rule("NON_EXISTENT") is False
        assert engine.disable_rule("NON_EXISTENT") is False

    def test_add_custom_rule(self) -> None:
        engine = RuleEngine()
        new_rule = RuleDefinition(
            id="CUSTOM_NEW",
            name="New Rule",
            description="Testing add rule",
            severity=RuleSeverity.CRITICAL,
            mitre_tactic="Execution",
            mitre_technique="T1059",
            conditions={},
        )
        engine.add_rule(new_rule)
        assert engine.get_rule("CUSTOM_NEW") is not None


class TestDetectionRules:
    @pytest.fixture()
    def engine(self) -> RuleEngine:
        return RuleEngine()

    def test_rule_auth_001_brute_force(self, engine: RuleEngine) -> None:
        event = SecurityEvent(
            timestamp=datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC),
            source_ip="192.168.1.100",
            event_type="authentication",
            action="failed",
            source="test",
            raw_data={},
        )
        fv = FeatureVector(
            event_id=event.event_id,
            timestamp=event.timestamp,
            entity_id="192.168.1.100",
            hour_of_day=12,
            day_of_week=4,
            is_weekend=False,
            is_off_hours=False,
            auth_failed_1m=5,
            auth_failure_burst=True,
        )
        matches = engine.evaluate(event, fv)
        rule_matches = [m for m in matches if m.rule_id == "RULE_AUTH_001"]
        assert len(rule_matches) == 1
        assert rule_matches[0].severity == "HIGH"
        assert rule_matches[0].mitre_technique == "T1110.001"
        assert rule_matches[0].evidence["failed_count"] == 5

    def test_rule_auth_002_password_spray(self, engine: RuleEngine) -> None:
        event = SecurityEvent(
            timestamp=datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC),
            source_ip="192.168.1.100",
            event_type="authentication",
            action="failed",
            source="test",
            raw_data={},
        )
        fv = FeatureVector(
            event_id=event.event_id,
            timestamp=event.timestamp,
            entity_id="192.168.1.100",
            hour_of_day=12,
            day_of_week=4,
            is_weekend=False,
            is_off_hours=False,
            unique_users_targeted_5m=4,
            auth_failed_5m=4,
        )
        matches = engine.evaluate(event, fv)
        rule_matches = [m for m in matches if m.rule_id == "RULE_AUTH_002"]
        assert len(rule_matches) == 1
        assert rule_matches[0].mitre_technique == "T1110.003"
        assert rule_matches[0].evidence["unique_users_targeted_5m"] == 4

    def test_rule_auth_003_login_after_failures(self, engine: RuleEngine) -> None:
        event = SecurityEvent(
            timestamp=datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC),
            source_ip="192.168.1.100",
            event_type="authentication",
            action="success",
            status="ok",
            source="test",
            raw_data={},
        )
        fv = FeatureVector(
            event_id=event.event_id,
            timestamp=event.timestamp,
            entity_id="192.168.1.100",
            hour_of_day=12,
            day_of_week=4,
            is_weekend=False,
            is_off_hours=False,
            auth_failed_5m=5,
        )
        matches = engine.evaluate(event, fv)
        rule_matches = [m for m in matches if m.rule_id == "RULE_AUTH_003"]
        assert len(rule_matches) == 1
        assert rule_matches[0].severity == "CRITICAL"

    def test_rule_net_001_port_scan(self, engine: RuleEngine) -> None:
        event = SecurityEvent(
            timestamp=datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC),
            source_ip="10.0.0.50",
            source="test",
            raw_data={},
        )
        fv = FeatureVector(
            event_id=event.event_id,
            timestamp=event.timestamp,
            entity_id="10.0.0.50",
            hour_of_day=12,
            day_of_week=4,
            is_weekend=False,
            is_off_hours=False,
            unique_dst_ports_5m=15,
        )
        matches = engine.evaluate(event, fv)
        rule_matches = [m for m in matches if m.rule_id == "RULE_NET_001"]
        assert len(rule_matches) == 1
        assert rule_matches[0].mitre_technique == "T1046"

    def test_rule_net_002_excessive_connections(self, engine: RuleEngine) -> None:
        event = SecurityEvent(
            timestamp=datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC),
            source_ip="10.0.0.50",
            source="test",
            raw_data={},
        )
        fv = FeatureVector(
            event_id=event.event_id,
            timestamp=event.timestamp,
            entity_id="10.0.0.50",
            hour_of_day=12,
            day_of_week=4,
            is_weekend=False,
            is_off_hours=False,
            conns_1m=60,
        )
        matches = engine.evaluate(event, fv)
        rule_matches = [m for m in matches if m.rule_id == "RULE_NET_002"]
        assert len(rule_matches) == 1

    def test_rule_net_003_exfiltration_volume(self, engine: RuleEngine) -> None:
        event = SecurityEvent(
            timestamp=datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC),
            source_ip="10.0.0.50",
            bytes_sent=15_000_000,
            source="test",
            raw_data={},
        )
        matches = engine.evaluate(event)
        rule_matches = [m for m in matches if m.rule_id == "RULE_NET_003"]
        assert len(rule_matches) == 1
        assert rule_matches[0].mitre_technique == "T1048"

    def test_rule_host_001_off_hours_admin(self, engine: RuleEngine) -> None:
        # 02:00 UTC (off-hours) with 'root' user
        event = SecurityEvent(
            timestamp=datetime(2026, 8, 28, 2, 0, 0, tzinfo=UTC),
            username="root",
            source="test",
            raw_data={},
        )
        matches = engine.evaluate(event)
        rule_matches = [m for m in matches if m.rule_id == "RULE_HOST_001"]
        assert len(rule_matches) == 1
        assert rule_matches[0].mitre_technique == "T1078"

    def test_rule_event_001_event_burst(self, engine: RuleEngine) -> None:
        event = SecurityEvent(
            timestamp=datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC),
            source_ip="192.168.1.1",
            source="test",
            raw_data={},
        )
        fv = FeatureVector(
            event_id=event.event_id,
            timestamp=event.timestamp,
            entity_id="192.168.1.1",
            hour_of_day=12,
            day_of_week=4,
            is_weekend=False,
            is_off_hours=False,
            events_1m=120,
        )
        matches = engine.evaluate(event, fv)
        rule_matches = [m for m in matches if m.rule_id == "RULE_EVENT_001"]
        assert len(rule_matches) == 1

    def test_rule_auth_004_multi_host_failures(self, engine: RuleEngine) -> None:
        event = SecurityEvent(
            timestamp=datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC),
            source_ip="192.168.1.200",
            source="test",
            raw_data={},
        )
        fv = FeatureVector(
            event_id=event.event_id,
            timestamp=event.timestamp,
            entity_id="192.168.1.200",
            hour_of_day=12,
            day_of_week=4,
            is_weekend=False,
            is_off_hours=False,
            unique_dst_ips_5m=4,
            auth_failed_5m=5,
        )
        matches = engine.evaluate(event, fv)
        rule_matches = [m for m in matches if m.rule_id == "RULE_AUTH_004"]
        assert len(rule_matches) == 1
        assert rule_matches[0].mitre_technique == "T1021"

    def test_rule_net_004_sensitive_port_access(self, engine: RuleEngine) -> None:
        # Access to RDP (port 3389)
        event = SecurityEvent(
            timestamp=datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC),
            destination_port=3389,
            protocol="TCP",
            source="test",
            raw_data={},
        )
        matches = engine.evaluate(event)
        rule_matches = [m for m in matches if m.rule_id == "RULE_NET_004"]
        assert len(rule_matches) == 1
        assert rule_matches[0].evidence["destination_port"] == 3389


class TestPipelineRuleIntegration:
    def test_pipeline_stream_with_rules(self) -> None:
        pipeline = FeaturePipeline()
        engine = RuleEngine()

        # Simulate 6 rapid failed authentication events from same source IP
        events = [
            SecurityEvent(
                timestamp=datetime(2026, 8, 28, 12, 0, i * 5, tzinfo=UTC),
                source_ip="172.16.0.100",
                event_type="authentication",
                action="failed",
                status="failure",
                source="test_stream",
                raw_data={},
            )
            for i in range(6)
        ]

        all_matches: list[RuleMatch] = []
        for event in events:
            fv = pipeline.process_event(event)
            matches = engine.evaluate(event, fv)
            all_matches.extend(matches)

        # Confirm RULE_AUTH_001 triggered on the 5th and 6th events
        brute_matches = [m for m in all_matches if m.rule_id == "RULE_AUTH_001"]
        assert len(brute_matches) >= 1
        assert brute_matches[0].entity_id == "172.16.0.100"
