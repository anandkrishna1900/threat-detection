"""Rule-based detection engine coordinating rule execution against event streams."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path

from src.common.logging_setup import get_logger
from src.detection.rules.evaluators import evaluate_rule
from src.detection.rules.loader import load_rules_from_yaml
from src.detection.rules.models import RuleDefinition, RuleMatch
from src.features.models import FeatureVector
from src.ingestion.models import SecurityEvent

logger = get_logger(__name__)


class RuleEngine:
    """Detection engine evaluating security events against configured rules."""

    def __init__(
        self,
        rules: list[RuleDefinition] | None = None,
        rules_file: str | Path | None = None,
    ) -> None:
        if rules is not None:
            self._rules: dict[str, RuleDefinition] = {r.id: r for r in rules}
        else:
            loaded_rules = load_rules_from_yaml(rules_file)
            self._rules = {r.id: r for r in loaded_rules}

        logger.info("rule_engine_initialized", total_rules=len(self._rules))

    @property
    def rules(self) -> list[RuleDefinition]:
        """Return all registered rules."""
        return list(self._rules.values())

    @property
    def active_rules(self) -> list[RuleDefinition]:
        """Return only enabled rules."""
        return [r for r in self._rules.values() if r.enabled]

    def get_rule(self, rule_id: str) -> RuleDefinition | None:
        """Get rule definition by ID."""
        return self._rules.get(rule_id)

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a specific rule by ID."""
        if rule_id in self._rules:
            self._rules[rule_id].enabled = True
            logger.info("rule_enabled", rule_id=rule_id)
            return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a specific rule by ID."""
        if rule_id in self._rules:
            self._rules[rule_id].enabled = False
            logger.info("rule_disabled", rule_id=rule_id)
            return True
        return False

    def add_rule(self, rule: RuleDefinition) -> None:
        """Add or update a rule definition."""
        self._rules[rule.id] = rule
        logger.info("rule_added", rule_id=rule.id)

    def evaluate(
        self, event: SecurityEvent, feature_vector: FeatureVector | None = None
    ) -> list[RuleMatch]:
        """Evaluate a single SecurityEvent against all active detection rules."""
        matches: list[RuleMatch] = []
        for rule in self.active_rules:
            match = evaluate_rule(rule, event, feature_vector)
            if match is not None:
                matches.append(match)
                logger.info(
                    "rule_triggered",
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=match.severity,
                    event_id=event.event_id,
                )
        return matches

    def evaluate_stream(
        self,
        stream: Iterable[tuple[SecurityEvent, FeatureVector | None]],
    ) -> Iterator[RuleMatch]:
        """Stream RuleMatch alerts over a stream of (SecurityEvent, FeatureVector) pairs."""
        for event, fv in stream:
            for match in self.evaluate(event, fv):
                yield match
