"""
Security Manager for VigilEdge WAF
Handles security policies, threat intelligence, and security rule management
"""

import asyncio
import json
import re
from typing import Dict, List, Optional, Set, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import ipaddress


class SecurityPolicy(Enum):
    """Security policy levels"""
    PERMISSIVE = "permissive"
    BALANCED = "balanced"
    STRICT = "strict"
    PARANOID = "paranoid"


@dataclass
class SecurityRule:
    """Security rule definition"""
    id: str
    name: str
    description: str
    pattern: str
    threat_type: str
    severity: str
    enabled: bool = True
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()


@dataclass
class ThreatIntelligence:
    """Threat intelligence data"""
    ip: str
    country: Optional[str] = None
    asn: Optional[str] = None
    reputation_score: int = 0
    threat_types: List[str] = None
    last_seen: datetime = None
    
    def __post_init__(self):
        if self.threat_types is None:
            self.threat_types = []
        if self.last_seen is None:
            self.last_seen = datetime.utcnow()


class SecurityManager:
    """
    Manages security policies, rules, and threat intelligence for the WAF
    """
    
    def __init__(self):
        self.security_policy = SecurityPolicy.BALANCED
        self.security_rules: Dict[str, SecurityRule] = {}
        self.threat_intelligence: Dict[str, ThreatIntelligence] = {}
        self.whitelist_ips: Set[str] = set()
        self.blacklist_ips: Set[str] = set()
        self.custom_patterns: List[re.Pattern] = []
        
        # Initialize default security rules
        self._init_default_rules()
        self._init_default_threat_intelligence()
    
    def _init_default_rules(self):
        """Initialize default security rules"""
        default_rules = [
            {
                "id": "SQL_001",
                "name": "SQL Injection - UNION SELECT",
                "description": "Detects UNION SELECT SQL injection attempts",
                "pattern": r"union\s+select",
                "threat_type": "sql_injection",
                "severity": "critical"
            },
            {
                "id": "SQL_002", 
                "name": "SQL Injection - DROP TABLE",
                "description": "Detects DROP TABLE SQL injection attempts",
                "pattern": r"drop\s+table",
                "threat_type": "sql_injection",
                "severity": "critical"
            },
            {
                "id": "XSS_001",
                "name": "XSS - Script Tags",
                "description": "Detects script tag XSS attempts",
                "pattern": r"<script[^>]*>.*?</script>",
                "threat_type": "xss",
                "severity": "high"
            },
            {
                "id": "XSS_002",
                "name": "XSS - JavaScript Protocol",
                "description": "Detects javascript: protocol XSS attempts",
                "pattern": r"javascript:",
                "threat_type": "xss",
                "severity": "high"
            },
            {
                "id": "LFI_001",
                "name": "Local File Inclusion",
                "description": "Detects local file inclusion attempts",
                "pattern": r"\.\.\/|\.\.\\",
                "threat_type": "lfi",
                "severity": "high"
            },
            {
                "id": "RFI_001",
                "name": "Remote File Inclusion",
                "description": "Detects remote file inclusion attempts",
                "pattern": r"http[s]?:\/\/.*\.(txt|php|asp|jsp)",
                "threat_type": "rfi",
                "severity": "high"
            },
            {
                "id": "CMD_001",
                "name": "Command Injection",
                "description": "Detects command injection attempts",
                "pattern": r"[;&|`]|\$\(|\${|<\(|>\(",
                "threat_type": "command_injection",
                "severity": "critical"
            }
        ]
        
        for rule_data in default_rules:
            rule = SecurityRule(**rule_data)
            self.security_rules[rule.id] = rule
    
    def _init_default_threat_intelligence(self):
        """Initialize default threat intelligence data"""
        # Known malicious IP ranges (example data)
        known_bad_ips = [
            "10.0.0.0/8",      # RFC1918 private
            "172.16.0.0/12",   # RFC1918 private
            "192.168.0.0/16",  # RFC1918 private
        ]
        
        # Add to blacklist (these are examples - in real implementation
        # you would load from threat intelligence feeds)
        for ip_range in known_bad_ips:
            try:
                network = ipaddress.ip_network(ip_range, strict=False)
                for ip in network.hosts():
                    if len(self.threat_intelligence) < 1000:  # Limit for demo
                        self.threat_intelligence[str(ip)] = ThreatIntelligence(
                            ip=str(ip),
                            reputation_score=-100,
                            threat_types=["known_malicious"]
                        )
            except Exception:
                continue
    
    async def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation and threat intelligence"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if IP is in whitelist
            if ip in self.whitelist_ips:
                return {
                    "status": "whitelisted",
                    "reputation_score": 100,
                    "threat_level": "none",
                    "action": "allow"
                }
            
            # Check if IP is in blacklist
            if ip in self.blacklist_ips:
                return {
                    "status": "blacklisted", 
                    "reputation_score": -100,
                    "threat_level": "critical",
                    "action": "block"
                }
            
            # Check threat intelligence
            if ip in self.threat_intelligence:
                intel = self.threat_intelligence[ip]
                return {
                    "status": "known",
                    "reputation_score": intel.reputation_score,
                    "threat_types": intel.threat_types,
                    "country": intel.country,
                    "asn": intel.asn,
                    "last_seen": intel.last_seen.isoformat(),
                    "threat_level": self._get_threat_level(intel.reputation_score),
                    "action": self._get_action_for_score(intel.reputation_score)
                }
            
            # Unknown IP - neutral reputation
            return {
                "status": "unknown",
                "reputation_score": 0,
                "threat_level": "low",
                "action": "allow"
            }
            
        except ValueError:
            # Invalid IP address
            return {
                "status": "invalid",
                "reputation_score": -50,
                "threat_level": "medium",
                "action": "block"
            }
    
    def _get_threat_level(self, score: int) -> str:
        """Convert reputation score to threat level"""
        if score >= 50:
            return "none"
        elif score >= 0:
            return "low"
        elif score >= -50:
            return "medium"
        elif score >= -80:
            return "high"
        else:
            return "critical"
    
    def _get_action_for_score(self, score: int) -> str:
        """Determine action based on reputation score and policy"""
        if self.security_policy == SecurityPolicy.PERMISSIVE:
            return "block" if score < -80 else "allow"
        elif self.security_policy == SecurityPolicy.BALANCED:
            return "block" if score < -50 else "allow"
        elif self.security_policy == SecurityPolicy.STRICT:
            return "block" if score < -20 else "allow"
        else:  # PARANOID
            return "block" if score < 0 else "allow"
    
    async def evaluate_security_rules(self, content: str) -> List[Dict[str, Any]]:
        """Evaluate content against security rules"""
        violations = []
        
        for rule_id, rule in self.security_rules.items():
            if not rule.enabled:
                continue
                
            try:
                pattern = re.compile(rule.pattern, re.IGNORECASE | re.DOTALL)
                matches = pattern.findall(content)
                
                if matches:
                    violations.append({
                        "rule_id": rule_id,
                        "rule_name": rule.name,
                        "threat_type": rule.threat_type,
                        "severity": rule.severity,
                        "matches": matches[:5],  # Limit matches for performance
                        "pattern": rule.pattern,
                        "description": rule.description
                    })
                    
            except re.error as e:
                # Log regex compilation error
                continue
        
        return violations
    
    async def add_security_rule(self, rule: SecurityRule) -> bool:
        """Add a new security rule"""
        try:
            # Validate regex pattern
            re.compile(rule.pattern)
            self.security_rules[rule.id] = rule
            return True
        except re.error:
            return False
    
    async def remove_security_rule(self, rule_id: str) -> bool:
        """Remove a security rule"""
        if rule_id in self.security_rules:
            del self.security_rules[rule_id]
            return True
        return False
    
    async def enable_rule(self, rule_id: str) -> bool:
        """Enable a security rule"""
        if rule_id in self.security_rules:
            self.security_rules[rule_id].enabled = True
            return True
        return False
    
    async def disable_rule(self, rule_id: str) -> bool:
        """Disable a security rule"""
        if rule_id in self.security_rules:
            self.security_rules[rule_id].enabled = False
            return True
        return False
    
    async def add_to_whitelist(self, ip: str) -> bool:
        """Add IP to whitelist"""
        try:
            ipaddress.ip_address(ip)
            self.whitelist_ips.add(ip)
            # Remove from blacklist if present
            self.blacklist_ips.discard(ip)
            return True
        except ValueError:
            return False
    
    async def add_to_blacklist(self, ip: str) -> bool:
        """Add IP to blacklist"""
        try:
            ipaddress.ip_address(ip)
            self.blacklist_ips.add(ip)
            # Remove from whitelist if present
            self.whitelist_ips.discard(ip)
            return True
        except ValueError:
            return False
    
    async def remove_from_whitelist(self, ip: str) -> bool:
        """Remove IP from whitelist"""
        if ip in self.whitelist_ips:
            self.whitelist_ips.remove(ip)
            return True
        return False
    
    async def remove_from_blacklist(self, ip: str) -> bool:
        """Remove IP from blacklist"""
        if ip in self.blacklist_ips:
            self.blacklist_ips.remove(ip)
            return True
        return False
    
    async def update_threat_intelligence(self, ip: str, intel: ThreatIntelligence):
        """Update threat intelligence for an IP"""
        self.threat_intelligence[ip] = intel
    
    async def get_security_summary(self) -> Dict[str, Any]:
        """Get security configuration summary"""
        return {
            "security_policy": self.security_policy.value,
            "total_rules": len(self.security_rules),
            "enabled_rules": len([r for r in self.security_rules.values() if r.enabled]),
            "disabled_rules": len([r for r in self.security_rules.values() if not r.enabled]),
            "whitelist_size": len(self.whitelist_ips),
            "blacklist_size": len(self.blacklist_ips),
            "threat_intel_entries": len(self.threat_intelligence),
            "rule_categories": self._get_rule_categories()
        }
    
    def _get_rule_categories(self) -> Dict[str, int]:
        """Get count of rules by threat type"""
        categories = {}
        for rule in self.security_rules.values():
            if rule.enabled:
                categories[rule.threat_type] = categories.get(rule.threat_type, 0) + 1
        return categories
    
    async def export_rules(self) -> List[Dict[str, Any]]:
        """Export security rules"""
        return [
            {
                "id": rule.id,
                "name": rule.name,
                "description": rule.description,
                "pattern": rule.pattern,
                "threat_type": rule.threat_type,
                "severity": rule.severity,
                "enabled": rule.enabled,
                "created_at": rule.created_at.isoformat()
            }
            for rule in self.security_rules.values()
        ]
    
    async def import_rules(self, rules_data: List[Dict[str, Any]]) -> int:
        """Import security rules"""
        imported_count = 0
        for rule_data in rules_data:
            try:
                rule = SecurityRule(**rule_data)
                if await self.add_security_rule(rule):
                    imported_count += 1
            except Exception:
                continue
        return imported_count
    
    async def set_security_policy(self, policy: SecurityPolicy):
        """Set security policy level"""
        self.security_policy = policy
    
    async def get_rule_by_id(self, rule_id: str) -> Optional[SecurityRule]:
        """Get security rule by ID"""
        return self.security_rules.get(rule_id)
    
    async def search_rules(self, search_term: str) -> List[SecurityRule]:
        """Search rules by name or description"""
        results = []
        search_term = search_term.lower()
        
        for rule in self.security_rules.values():
            if (search_term in rule.name.lower() or 
                search_term in rule.description.lower() or
                search_term in rule.threat_type.lower()):
                results.append(rule)
        
        return results
