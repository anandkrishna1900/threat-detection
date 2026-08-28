"""YAML loader for detection rule definitions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from src.common.config import get_config
from src.common.logging_setup import get_logger
from src.detection.rules.models import RuleDefinition

logger = get_logger(__name__)


def load_rules_from_yaml(file_path: str | Path | None = None) -> list[RuleDefinition]:
    """Load and validate detection rules from a YAML configuration file."""
    if file_path is None:
        cfg = get_config()
        file_path = cfg.config_dir / "detection_rules.yaml"

    path = Path(file_path)
    if not path.exists():
        logger.warning("rules_file_not_found", path=str(path))
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_content = yaml.safe_load(f)
    except Exception as exc:
        logger.error("rules_yaml_parse_error", path=str(path), error=str(exc))
        return []

    if not isinstance(raw_content, dict) or "rules" not in raw_content:
        logger.warning("rules_yaml_invalid_structure", path=str(path))
        return []

    rules: list[RuleDefinition] = []
    for raw_rule in raw_content.get("rules", []):
        if not isinstance(raw_rule, dict):
            continue
        try:
            rule_def = RuleDefinition(**raw_rule)
            rules.append(rule_def)
        except Exception as exc:
            logger.warning(
                "rule_validation_failed",
                rule_id=raw_rule.get("id", "unknown"),
                error=str(exc),
            )

    logger.info("rules_loaded_successfully", count=len(rules), path=str(path))
    return rules


def load_rules_from_dict(raw_dict: dict[str, Any]) -> list[RuleDefinition]:
    """Load and validate detection rules from an in-memory dictionary."""
    rules_list = raw_dict.get("rules", []) if isinstance(raw_dict, dict) else []
    rules: list[RuleDefinition] = []
    for raw_rule in rules_list:
        if isinstance(raw_rule, dict):
            try:
                rules.append(RuleDefinition(**raw_rule))
            except Exception:
                continue
    return rules
