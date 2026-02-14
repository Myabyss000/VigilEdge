"""
MITRE ATT&CK mapping - maps attack types and techniques to MITRE framework.
"""
import logging
from typing import Dict, Optional

logger = logging.getLogger("threatloom.detection.mitre")


# MITRE ATT&CK Enterprise mapping for web-focused attack types
MITRE_MAP: Dict[str, Dict[str, str]] = {
    # Attack Type -> {tactic, technique, technique_name}
    "SQLI": {
        "tactic": "Initial Access",
        "technique": "T1190",
        "technique_name": "Exploit Public-Facing Application",
    },
    "XSS": {
        "tactic": "Initial Access",
        "technique": "T1189",
        "technique_name": "Drive-by Compromise",
    },
    "RCE": {
        "tactic": "Execution",
        "technique": "T1059",
        "technique_name": "Command and Scripting Interpreter",
    },
    "LFI": {
        "tactic": "Collection",
        "technique": "T1005",
        "technique_name": "Data from Local System",
    },
    "RFI": {
        "tactic": "Execution",
        "technique": "T1059",
        "technique_name": "Command and Scripting Interpreter",
    },
    "BRUTE_FORCE": {
        "tactic": "Credential Access",
        "technique": "T1110",
        "technique_name": "Brute Force",
    },
    "PORT_SCAN": {
        "tactic": "Reconnaissance",
        "technique": "T1046",
        "technique_name": "Network Service Discovery",
    },
    "DDOS": {
        "tactic": "Impact",
        "technique": "T1498",
        "technique_name": "Network Denial of Service",
    },
    "DIRECTORY_TRAVERSAL": {
        "tactic": "Collection",
        "technique": "T1083",
        "technique_name": "File and Directory Discovery",
    },
    "COMMAND_INJECTION": {
        "tactic": "Execution",
        "technique": "T1059",
        "technique_name": "Command and Scripting Interpreter",
    },
    "SSRF": {
        "tactic": "Initial Access",
        "technique": "T1190",
        "technique_name": "Exploit Public-Facing Application",
    },
    "XXE": {
        "tactic": "Initial Access",
        "technique": "T1190",
        "technique_name": "Exploit Public-Facing Application",
    },
    "CSRF": {
        "tactic": "Initial Access",
        "technique": "T1189",
        "technique_name": "Drive-by Compromise",
    },
    "BOT": {
        "tactic": "Reconnaissance",
        "technique": "T1595",
        "technique_name": "Active Scanning",
    },
}


class MITREMapper:
    """Map firewall attack types to MITRE ATT&CK framework."""

    def __init__(self):
        self.mapping = MITRE_MAP

    def map_attack(self, attack_type: str) -> dict:
        """
        Map an attack type to MITRE ATT&CK tactic and technique.

        Returns:
            dict with keys: tactic, technique, technique_name
            Empty dict if no mapping exists.
        """
        attack_upper = attack_type.upper().replace(" ", "_").replace("-", "_")
        return self.mapping.get(attack_upper, {})

    def get_tactic(self, attack_type: str) -> Optional[str]:
        m = self.map_attack(attack_type)
        return m.get("tactic")

    def get_technique(self, attack_type: str) -> Optional[str]:
        m = self.map_attack(attack_type)
        return m.get("technique")

    def get_all_tactics(self) -> list:
        """Return all unique MITRE tactics in the mapping."""
        return sorted(set(v["tactic"] for v in self.mapping.values()))

    def get_all_techniques(self) -> list:
        """Return all MITRE techniques in the mapping."""
        return [
            {"id": v["technique"], "name": v["technique_name"], "tactic": v["tactic"]}
            for v in self.mapping.values()
        ]
