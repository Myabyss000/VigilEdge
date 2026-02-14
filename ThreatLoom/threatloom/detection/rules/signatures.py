"""
Signature-based detection - matches log fields against defined patterns.
"""
import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger("threatloom.detection.signatures")


class SignatureDetector:
    """Evaluate logs against signature-based detection rules."""

    def __init__(self):
        self.rules: List[Dict[str, Any]] = []

    def add_rule(self, rule: dict):
        """Register a signature rule."""
        self.rules.append(rule)

    def evaluate(self, log) -> List[dict]:
        """Check a log against all signature rules. Returns matched rule dicts."""
        hits = []
        for rule in self.rules:
            if not rule.get("enabled", True):
                continue
            if self._matches(log, rule):
                hits.append({
                    "rule_id": rule.get("id"),
                    "title": rule.get("name") or rule.get("title", "Unknown rule"),
                    "description": rule.get("description"),
                    "severity": rule.get("severity", "MEDIUM"),
                    "confidence": rule.get("confidence", 0.85),
                    "mitre_tactic": rule.get("mitre_tactic"),
                    "mitre_technique": rule.get("mitre_technique"),
                })
        return hits

    def _matches(self, log, rule: dict) -> bool:
        """Check if a log matches a rule's conditions.

        Conditions can be:
          - a list of {field, operator, value} dicts  (YAML rule format)
          - a flat dict  {field: value}               (legacy format)
        """
        conditions = rule.get("conditions", {})
        if not conditions:
            return False

        # --- list-of-dicts format (from YAML rules) ---
        if isinstance(conditions, list):
            for cond in conditions:
                field = cond.get("field", "")
                operator = cond.get("operator", "equals")
                expected = cond.get("value", "")
                actual_value = self._get_field(log, field)

                if actual_value is None:
                    return False

                actual_str = (
                    actual_value.value
                    if hasattr(actual_value, "value")
                    else str(actual_value)
                )

                if operator == "equals":
                    if actual_str != str(expected):
                        return False
                elif operator == "not_equals":
                    if actual_str == str(expected):
                        return False
                elif operator == "contains":
                    if str(expected).lower() not in actual_str.lower():
                        return False
                elif operator == "regex":
                    if not re.search(str(expected), actual_str, re.I):
                        return False
                elif operator == "in":
                    if actual_str not in [str(v) for v in expected]:
                        return False
                elif operator == "gt":
                    try:
                        if float(actual_str) <= float(expected):
                            return False
                    except (ValueError, TypeError):
                        return False
                elif operator == "lt":
                    try:
                        if float(actual_str) >= float(expected):
                            return False
                    except (ValueError, TypeError):
                        return False
                else:
                    logger.warning("Unknown operator '%s' in rule — skipping", operator)
            return True

        # --- flat-dict format (legacy) ---
        for field, expected in conditions.items():
            actual_value = self._get_field(log, field)
            if actual_value is None:
                return False
            actual_str = (
                actual_value.value
                if hasattr(actual_value, "value")
                else str(actual_value)
            )
            if actual_str != str(expected):
                return False

        return True

    @staticmethod
    def _get_field(log, field: str):
        """Safely get a field from a log entry (supports ORM objects and dicts)."""
        if isinstance(log, dict):
            return log.get(field)
        return getattr(log, field, None)
