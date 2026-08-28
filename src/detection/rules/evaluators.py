"""Rule evaluation strategies for security events and feature vectors."""

from __future__ import annotations

from typing import Any

from src.detection.rules.models import RuleDefinition, RuleMatch
from src.features.models import FeatureVector
from src.ingestion.models import SecurityEvent


def evaluate_rule(
    rule: RuleDefinition,
    event: SecurityEvent,
    feature_vector: FeatureVector | None = None,
) -> RuleMatch | None:
    """Evaluate a single rule against a SecurityEvent and optional FeatureVector."""
    if not rule.enabled:
        return None

    rule_id = rule.id
    conditions = rule.conditions

    # Dispatch to specific evaluator if known, or generic evaluator
    match_evidence = None

    if rule_id == "RULE_AUTH_001":
        match_evidence = _eval_auth_001(conditions, event, feature_vector)
    elif rule_id == "RULE_AUTH_002":
        match_evidence = _eval_auth_002(conditions, event, feature_vector)
    elif rule_id == "RULE_AUTH_003":
        match_evidence = _eval_auth_003(conditions, event, feature_vector)
    elif rule_id == "RULE_NET_001":
        match_evidence = _eval_net_001(conditions, event, feature_vector)
    elif rule_id == "RULE_NET_002":
        match_evidence = _eval_net_002(conditions, event, feature_vector)
    elif rule_id == "RULE_NET_003":
        match_evidence = _eval_net_003(conditions, event, feature_vector)
    elif rule_id == "RULE_HOST_001":
        match_evidence = _eval_host_001(conditions, event, feature_vector)
    elif rule_id == "RULE_EVENT_001":
        match_evidence = _eval_event_001(conditions, event, feature_vector)
    elif rule_id == "RULE_AUTH_004":
        match_evidence = _eval_auth_004(conditions, event, feature_vector)
    elif rule_id == "RULE_NET_004":
        match_evidence = _eval_net_004(conditions, event, feature_vector)
    else:
        # Generic condition evaluator
        match_evidence = _eval_generic(conditions, event, feature_vector)

    if match_evidence is not None:
        entity_id = (
            feature_vector.entity_id
            if feature_vector
            else (event.source_ip or event.username or event.hostname or "unknown")
        )
        return RuleMatch(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity.value if hasattr(rule.severity, "value") else str(rule.severity),
            confidence=rule.confidence,
            entity_id=entity_id,
            matched_event_id=event.event_id,
            timestamp=event.timestamp,
            mitre_tactic=rule.mitre_tactic,
            mitre_technique=rule.mitre_technique,
            evidence=match_evidence,
        )

    return None


def _eval_auth_001(
    conditions: dict[str, Any], event: SecurityEvent, fv: FeatureVector | None
) -> dict[str, Any] | None:
    threshold = conditions.get("auth_failed_count", 5)
    window_sec = conditions.get("window_seconds", 60)

    if fv is not None:
        failed_count = fv.auth_failed_1m if window_sec <= 60 else fv.auth_failed_5m
        if failed_count >= threshold or fv.auth_failure_burst:
            return {
                "failed_count": failed_count,
                "threshold": threshold,
                "window_seconds": window_sec,
                "auth_failure_burst": fv.auth_failure_burst,
            }
    return None


def _eval_auth_002(
    conditions: dict[str, Any], event: SecurityEvent, fv: FeatureVector | None
) -> dict[str, Any] | None:
    users_threshold = conditions.get("unique_users_targeted", 3)
    fails_threshold = conditions.get("auth_failed_count", 3)

    if fv is not None:
        if fv.unique_users_targeted_5m >= users_threshold and fv.auth_failed_5m >= fails_threshold:
            return {
                "unique_users_targeted_5m": fv.unique_users_targeted_5m,
                "users_threshold": users_threshold,
                "auth_failed_5m": fv.auth_failed_5m,
                "fails_threshold": fails_threshold,
            }
    return None


def _eval_auth_003(
    conditions: dict[str, Any], event: SecurityEvent, fv: FeatureVector | None
) -> dict[str, Any] | None:
    prior_thresh = conditions.get("prior_failures_threshold", 3)

    # Check if current event is an authentication success
    is_success = False
    if event.event_type == "authentication" or event.action in (
        "login",
        "auth",
        "authenticate",
        "success",
    ):
        if event.action == "success" or event.status in ("success", "SUCCESS", "ok"):
            is_success = True

    if is_success and fv is not None:
        if fv.auth_failed_5m >= prior_thresh:
            return {
                "event_status": "success",
                "prior_failed_logins_5m": fv.auth_failed_5m,
                "threshold": prior_thresh,
            }
    return None


def _eval_net_001(
    conditions: dict[str, Any], event: SecurityEvent, fv: FeatureVector | None
) -> dict[str, Any] | None:
    ports_thresh = conditions.get("unique_dst_ports", 10)
    if fv is not None and fv.unique_dst_ports_5m >= ports_thresh:
        return {
            "unique_dst_ports_5m": fv.unique_dst_ports_5m,
            "threshold": ports_thresh,
        }
    return None


def _eval_net_002(
    conditions: dict[str, Any], event: SecurityEvent, fv: FeatureVector | None
) -> dict[str, Any] | None:
    conns_thresh = conditions.get("conns_1m", 50)
    if fv is not None and fv.conns_1m >= conns_thresh:
        return {
            "conns_1m": fv.conns_1m,
            "threshold": conns_thresh,
        }
    return None


def _eval_net_003(
    conditions: dict[str, Any], event: SecurityEvent, fv: FeatureVector | None
) -> dict[str, Any] | None:
    bytes_thresh = float(conditions.get("bytes_sent_threshold", 10_000_000.0))
    event_bytes = float(event.bytes_sent or 0)
    fv_bytes = fv.bytes_sent if fv else 0.0

    actual_bytes = max(event_bytes, fv_bytes)
    if actual_bytes >= bytes_thresh:
        return {
            "bytes_sent": actual_bytes,
            "threshold": bytes_thresh,
        }
    return None


def _eval_host_001(
    conditions: dict[str, Any], event: SecurityEvent, fv: FeatureVector | None
) -> dict[str, Any] | None:
    admin_users = {
        u.lower()
        for u in conditions.get("admin_usernames", ["root", "admin", "administrator", "system"])
    }
    user = (event.username or "").lower().strip()

    is_off_hours = (
        fv.is_off_hours
        if fv is not None
        else (event.timestamp.hour < 8 or event.timestamp.hour >= 18)
    )

    if user in admin_users and is_off_hours:
        return {
            "username": event.username,
            "hour_of_day": fv.hour_of_day if fv else event.timestamp.hour,
            "is_off_hours": is_off_hours,
        }
    return None


def _eval_event_001(
    conditions: dict[str, Any], event: SecurityEvent, fv: FeatureVector | None
) -> dict[str, Any] | None:
    events_thresh = conditions.get("events_1m", 100)
    if fv is not None and fv.events_1m >= events_thresh:
        return {
            "events_1m": fv.events_1m,
            "threshold": events_thresh,
        }
    return None


def _eval_auth_004(
    conditions: dict[str, Any], event: SecurityEvent, fv: FeatureVector | None
) -> dict[str, Any] | None:
    ips_thresh = conditions.get("unique_dst_ips", 3)
    fails_thresh = conditions.get("auth_failed_count", 3)

    if fv is not None:
        if fv.unique_dst_ips_5m >= ips_thresh and fv.auth_failed_5m >= fails_thresh:
            return {
                "unique_dst_ips_5m": fv.unique_dst_ips_5m,
                "ips_threshold": ips_thresh,
                "auth_failed_5m": fv.auth_failed_5m,
                "fails_threshold": fails_thresh,
            }
    return None


def _eval_net_004(
    conditions: dict[str, Any], event: SecurityEvent, fv: FeatureVector | None
) -> dict[str, Any] | None:
    sensitive_ports = set(
        conditions.get("sensitive_ports", [22, 23, 3389, 445, 1433, 3306, 5432, 27017])
    )
    matched_ports = []
    if event.destination_port in sensitive_ports:
        matched_ports.append(event.destination_port)
    if event.source_port in sensitive_ports:
        matched_ports.append(event.source_port)

    if matched_ports:
        return {
            "matched_port": matched_ports[0],
            "destination_port": event.destination_port,
            "source_port": event.source_port,
            "protocol": event.protocol,
        }
    return None


def _eval_generic(
    conditions: dict[str, Any], event: SecurityEvent, fv: FeatureVector | None
) -> dict[str, Any] | None:
    """Evaluate custom field-level comparison conditions."""
    matched = True
    evidence: dict[str, Any] = {}

    for k, expected in conditions.items():
        actual = getattr(event, k, None)
        if actual is None and fv is not None:
            actual = getattr(fv, k, None)

        if actual != expected:
            matched = False
            break
        evidence[k] = actual

    return evidence if matched and evidence else None
