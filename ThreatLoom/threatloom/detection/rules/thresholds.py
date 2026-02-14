"""
Threshold-based detection - triggers when event counts exceed limits within time windows.
"""
import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Any

logger = logging.getLogger("threatloom.detection.thresholds")


class ThresholdDetector:
    """Count-based detection: fires when thresholds are exceeded in time windows."""

    def __init__(self):
        self.rules: List[Dict[str, Any]] = []
        # Track event counts: {rule_id: {group_key: [(timestamp, log_id), ...]}}
        self._counters: Dict[str, Dict[str, list]] = defaultdict(lambda: defaultdict(list))

    def add_rule(self, rule: dict):
        """Register a threshold rule."""
        self.rules.append(rule)

    def evaluate_batch(self, logs: list) -> List[dict]:
        """Evaluate a batch of logs against threshold rules."""
        hits = []
        now = datetime.utcnow()

        for rule in self.rules:
            # YAML rules store threshold config in a nested dict
            thr_cfg = rule.get("threshold", {})
            if isinstance(thr_cfg, dict):
                threshold_count = thr_cfg.get("count", 10)
                window_seconds = thr_cfg.get("window_seconds", 60)
                group_by = thr_cfg.get("field", "src_ip")
                filter_conditions = thr_cfg.get("filter", {})
            else:
                # Legacy flat format
                threshold_count = rule.get("threshold", 10)
                window_seconds = rule.get("window_seconds", 60)
                group_by = rule.get("group_by", "src_ip")
                filter_conditions = rule.get("conditions", {})

            for log in logs:
                # Check if log matches the rule's filter conditions
                if not self._matches_conditions(log, filter_conditions):
                    continue

                # Group key
                group_key = self._get_field(log, group_by) or "unknown"
                log_id = log.id if hasattr(log, 'id') else id(log)
                ts = log.timestamp if hasattr(log, 'timestamp') else now

                # Add to counter
                counter = self._counters[rule["id"]][group_key]
                counter.append((ts, log_id))

                # Prune old entries
                cutoff = now - timedelta(seconds=window_seconds)
                counter[:] = [(t, lid) for t, lid in counter if t >= cutoff]

                # Check threshold
                if len(counter) >= threshold_count:
                    hits.append({
                        "rule_id": rule.get("id"),
                        "title": rule.get("title", f"Threshold exceeded: {rule['id']}"),
                        "description": (
                            f"{len(counter)} events from {group_key} in "
                            f"{window_seconds}s (threshold: {threshold_count})"
                        ),
                        "severity": rule.get("severity", "HIGH"),
                        "src_ip": group_key if group_by == "src_ip" else None,
                        "event_count": len(counter),
                        "log_ids": [lid for _, lid in counter],
                        "confidence": min(0.95, 0.5 + (len(counter) / threshold_count) * 0.3),
                    })
                    # Reset counter after alert
                    counter.clear()

        return hits

    def _matches_conditions(self, log, conditions) -> bool:
        """Check if a log matches base conditions for a threshold rule."""
        if not conditions:
            return True

        # Handle dict format (used in threshold filter)
        if isinstance(conditions, dict):
            for field, expected in conditions.items():
                actual = self._get_field(log, field)
                if actual is None:
                    return False
                actual_str = actual.value if hasattr(actual, 'value') else str(actual)
                if actual_str != str(expected):
                    return False
            return True

        # Handle list-of-dicts format (same as signature conditions)
        if isinstance(conditions, list):
            for cond in conditions:
                field = cond.get("field", "")
                operator = cond.get("operator", "equals")
                expected = cond.get("value", "")
                actual = self._get_field(log, field)
                if actual is None:
                    return False
                actual_str = actual.value if hasattr(actual, 'value') else str(actual)

                if operator == "equals" and actual_str != str(expected):
                    return False
                elif operator == "not_equals" and actual_str == str(expected):
                    return False
                elif operator == "contains" and str(expected).lower() not in actual_str.lower():
                    return False
                elif operator == "regex" and not re.search(str(expected), actual_str, re.I):
                    return False
            return True

        return True

    @staticmethod
    def _get_field(log, field: str):
        if isinstance(log, dict):
            return log.get(field)
        return getattr(log, field, None)

