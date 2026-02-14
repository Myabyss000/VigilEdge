"""
Rule engine - loads and evaluates detection rules against firewall logs.
"""
import logging
import os
from typing import List, Dict, Any

import yaml

from threatloom.detection.rules.signatures import SignatureDetector
from threatloom.detection.rules.thresholds import ThresholdDetector

logger = logging.getLogger("threatloom.detection.rules")

DEFAULT_RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "rules", "default_rules.yaml")


class RuleEngine:
    """
    Loads detection rules from YAML and evaluates logs against them.

    Rule types:
      - signature: pattern-matching on log fields
      - threshold: count-based triggers over time windows
    """

    def __init__(self, rules_path: str = None):
        self.rules_path = rules_path or DEFAULT_RULES_PATH
        self.rules: List[Dict[str, Any]] = []
        self.signature_detector = SignatureDetector()
        self.threshold_detector = ThresholdDetector()
        self._load_rules()

    def _load_rules(self):
        """Load rules from YAML file."""
        try:
            if os.path.exists(self.rules_path):
                with open(self.rules_path, "r") as f:
                    data = yaml.safe_load(f) or {}
                self.rules = data.get("rules", [])
                # Index rules by type
                for rule in self.rules:
                    if rule.get("type") == "signature":
                        self.signature_detector.add_rule(rule)
                    elif rule.get("type") == "threshold":
                        self.threshold_detector.add_rule(rule)
                logger.info(f"Loaded {len(self.rules)} detection rules.")
            else:
                logger.warning(f"Rules file not found: {self.rules_path}")
                self._load_builtin_rules()
        except Exception as e:
            logger.error(f"Failed to load rules: {e}")
            self._load_builtin_rules()

    def _load_builtin_rules(self):
        """Fallback built-in rules."""
        builtins = [
            {
                "id": "BUILTIN-001",
                "type": "signature",
                "title": "SQL Injection Detected",
                "description": "Request contains SQL injection patterns",
                "severity": "HIGH",
                "conditions": {"attack_type": "SQLI"},
            },
            {
                "id": "BUILTIN-002",
                "type": "signature",
                "title": "XSS Attack Detected",
                "description": "Request contains cross-site scripting patterns",
                "severity": "HIGH",
                "conditions": {"attack_type": "XSS"},
            },
            {
                "id": "BUILTIN-003",
                "type": "signature",
                "title": "Remote Code Execution Attempt",
                "description": "Request contains RCE patterns",
                "severity": "CRITICAL",
                "conditions": {"attack_type": "RCE"},
            },
            {
                "id": "BUILTIN-004",
                "type": "signature",
                "title": "Local File Inclusion Attempt",
                "description": "Request contains LFI/path traversal patterns",
                "severity": "HIGH",
                "conditions": {"attack_type": "LFI"},
            },
            {
                "id": "BUILTIN-005",
                "type": "signature",
                "title": "Blocked Request",
                "description": "Firewall blocked a request",
                "severity": "MEDIUM",
                "conditions": {"action": "BLOCKED", "attack_type_not": "NONE"},
            },
        ]
        for rule in builtins:
            self.signature_detector.add_rule(rule)
        self.rules = builtins
        logger.info(f"Loaded {len(builtins)} built-in detection rules.")

    def evaluate(self, log) -> List[dict]:
        """Evaluate a log entry against all rules. Returns list of hit dicts."""
        hits = []

        # Signature matches
        sig_hits = self.signature_detector.evaluate(log)
        hits.extend(sig_hits)

        return hits

    def reload_rules(self):
        """Hot-reload rules from file."""
        self.rules.clear()
        self.signature_detector = SignatureDetector()
        self.threshold_detector = ThresholdDetector()
        self._load_rules()
        logger.info("Rules reloaded.")
