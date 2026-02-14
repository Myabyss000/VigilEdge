"""
Minimal heuristic AI scorer for VigilEdge WAF.
Safe, dependency-free, observe-only scoring. Returns a small dict with
`ai_score` (0.0-1.0), `ai_confidence` and a short `note` explaining reason.

This is intentionally simple: it's a lightweight heuristic that combines
available indicators (ddos score, user-agent heuristics, blacklist flag)
and produces a normalized score. No external ML libraries required.

Now includes LM Studio integration for advanced AI scoring.
"""
from typing import Any, Dict, Optional, List
import os
import math
import json
import asyncio
from enum import Enum

try:
    import joblib
except Exception:
    joblib = None

try:
    from sentence_transformers import SentenceTransformer
except Exception:
    SentenceTransformer = None

try:
    import httpx
    HAVE_HTTPX = True
except Exception:
    HAVE_HTTPX = False


class ScorerType(str, Enum):
    """Available AI scoring methods"""
    HEURISTIC = "heuristic"
    LM_STUDIO = "lm_studio"
    HYBRID = "hybrid"  # Uses both and averages


# Global scorer configuration
_scorer_config = {
    "active_scorer": ScorerType.HEURISTIC,
    "lm_studio_url": "http://localhost:1234/v1/chat/completions",
    "lm_studio_timeout": 10.0,
    "lm_studio_available": False,
    "hybrid_weight_heuristic": 0.4,
    "hybrid_weight_lm_studio": 0.6,
}


def get_scorer_config() -> dict:
    """Get current scorer configuration"""
    return _scorer_config.copy()


def set_active_scorer(scorer_type: str) -> dict:
    """Switch between scoring methods"""
    global _scorer_config
    try:
        _scorer_config["active_scorer"] = ScorerType(scorer_type)
        return {"success": True, "active_scorer": scorer_type}
    except ValueError:
        return {"success": False, "error": f"Invalid scorer type. Use: {[s.value for s in ScorerType]}"}


class LMStudioScorer:
    """LM Studio-powered AI scorer for advanced threat analysis.
    
    Uses a local LLM to analyze security events and provide intelligent scoring.
    Falls back to heuristic scoring if LM Studio is unavailable.
    """
    
    def __init__(self, base_url: str = "http://localhost:1234"):
        self.base_url = base_url
        self.chat_endpoint = f"{base_url}/v1/chat/completions"
        self.models_endpoint = f"{base_url}/v1/models"
        self.timeout = 10.0
        self.is_available = False
        self._check_availability()
    
    def _check_availability(self) -> bool:
        """Check if LM Studio is running and accessible"""
        global _scorer_config
        if not HAVE_HTTPX:
            self.is_available = False
            _scorer_config["lm_studio_available"] = False
            return False
        
        try:
            import httpx
            with httpx.Client(timeout=2.0) as client:
                response = client.get(self.models_endpoint)
                self.is_available = response.status_code == 200
                _scorer_config["lm_studio_available"] = self.is_available
                return self.is_available
        except Exception:
            self.is_available = False
            _scorer_config["lm_studio_available"] = False
            return False
    
    def _build_analysis_prompt(self, event: Any) -> str:
        """Build a structured prompt for the LLM to analyze the security event"""
        details = getattr(event, "details", {}) or {}
        
        # Extract event information
        threat_type = getattr(event, "threat_type", details.get("threat_type", "unknown"))
        source_ip = getattr(event, "source_ip", details.get("source_ip", "unknown"))
        url = getattr(event, "url", getattr(event, "target_url", "")) or ""
        user_agent = getattr(event, "user_agent", details.get("user_agent", "")) or ""
        method = getattr(event, "method", details.get("method", "GET"))
        was_blocked = getattr(event, "blocked", details.get("blocked", False))
        ddos_score = details.get("ddos_score", 0)
        
        prompt = f"""Analyze this web security event and provide a threat score.

EVENT DETAILS:
- Threat Type: {threat_type}
- Source IP: {source_ip}
- HTTP Method: {method}
- Target URL: {url[:200] if url else 'N/A'}
- User Agent: {user_agent[:100] if user_agent else 'N/A'}
- Was Blocked: {was_blocked}
- DDoS Indicator Score: {ddos_score}

INSTRUCTIONS:
1. Analyze the severity of this security event
2. Consider the threat type, attack patterns in the URL, and user agent
3. Provide your assessment in this EXACT JSON format:

{{"score": 0.XX, "confidence": 0.XX, "severity": "low/medium/high/critical", "analysis": "brief explanation"}}

SCORING GUIDE:
- 0.0-0.3: Low risk (benign or false positive)
- 0.3-0.5: Medium risk (suspicious activity)
- 0.5-0.7: High risk (likely attack)
- 0.7-1.0: Critical risk (confirmed attack)

Respond ONLY with the JSON object, no other text."""

        return prompt
    
    async def score_event_async(self, event: Any) -> Dict[str, Any]:
        """Asynchronously score an event using LM Studio"""
        if not HAVE_HTTPX:
            return self._fallback_score(event, "httpx not installed")
        
        if not self.is_available:
            self._check_availability()
            if not self.is_available:
                return self._fallback_score(event, "LM Studio not available")
        
        prompt = self._build_analysis_prompt(event)
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.chat_endpoint,
                    json={
                        "messages": [
                            {"role": "system", "content": "You are a cybersecurity expert AI. Analyze security events and provide threat scores in JSON format only."},
                            {"role": "user", "content": prompt}
                        ],
                        "temperature": 0.3,
                        "max_tokens": 200,
                        "stream": False
                    }
                )
                
                if response.status_code != 200:
                    return self._fallback_score(event, f"LM Studio error: {response.status_code}")
                
                result = response.json()
                ai_response = result["choices"][0]["message"]["content"]
                
                # Parse the JSON response
                return self._parse_llm_response(ai_response, event)
                
        except asyncio.TimeoutError:
            return self._fallback_score(event, "LM Studio timeout")
        except Exception as e:
            return self._fallback_score(event, f"LM Studio error: {str(e)}")
    
    def score_event_sync(self, event: Any) -> Dict[str, Any]:
        """Synchronously score an event using LM Studio"""
        if not HAVE_HTTPX:
            return self._fallback_score(event, "httpx not installed")
        
        if not self.is_available:
            self._check_availability()
            if not self.is_available:
                return self._fallback_score(event, "LM Studio not available")
        
        prompt = self._build_analysis_prompt(event)
        
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    self.chat_endpoint,
                    json={
                        "messages": [
                            {"role": "system", "content": "You are a cybersecurity expert AI. Analyze security events and provide threat scores in JSON format only."},
                            {"role": "user", "content": prompt}
                        ],
                        "temperature": 0.3,
                        "max_tokens": 200,
                        "stream": False
                    }
                )
                
                if response.status_code != 200:
                    return self._fallback_score(event, f"LM Studio error: {response.status_code}")
                
                result = response.json()
                ai_response = result["choices"][0]["message"]["content"]
                
                # Parse the JSON response
                return self._parse_llm_response(ai_response, event)
                
        except Exception as e:
            return self._fallback_score(event, f"LM Studio error: {str(e)}")
    
    def _parse_llm_response(self, response_text: str, event: Any) -> Dict[str, Any]:
        """Parse the LLM's JSON response"""
        try:
            # Try to extract JSON from the response
            response_text = response_text.strip()
            
            # Handle markdown code blocks
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0]
            elif "```" in response_text:
                response_text = response_text.split("```")[1].split("```")[0]
            
            data = json.loads(response_text)
            
            score = float(data.get("score", 0.5))
            confidence = float(data.get("confidence", 0.7))
            severity = data.get("severity", "medium")
            analysis = data.get("analysis", "LLM analysis")
            
            # Clamp values
            score = max(0.0, min(1.0, score))
            confidence = max(0.0, min(1.0, confidence))
            
            return {
                "ai_score": round(score, 3),
                "ai_confidence": round(confidence, 3),
                "note": f"LLM:{severity} - {analysis[:50]}",
                "scorer_type": "lm_studio",
                "llm_severity": severity,
                "llm_analysis": analysis
            }
            
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            # If parsing fails, try to extract score from text
            return self._fallback_score(event, f"Parse error: {str(e)}")
    
    def _fallback_score(self, event: Any, reason: str) -> Dict[str, Any]:
        """Provide a fallback score when LM Studio fails"""
        # Use a simple heuristic as fallback
        details = getattr(event, "details", {}) or {}
        threat_type = getattr(event, "threat_type", details.get("threat_type", "none"))
        was_blocked = getattr(event, "blocked", details.get("blocked", False))
        
        if threat_type and threat_type != "none":
            score = 0.7 if was_blocked else 0.5
        else:
            score = 0.2
        
        return {
            "ai_score": score,
            "ai_confidence": 0.4,
            "note": f"fallback:{reason}",
            "scorer_type": "fallback",
            "fallback_reason": reason
        }


class HeuristicScorer:
    """Enhanced heuristic scorer with multi-factor analysis for accurate threat detection.

    Uses pattern matching, payload analysis, behavioral indicators, and contextual scoring
    to provide comprehensive threat assessment without changing firewall actions.
    """

    def __init__(self) -> None:
        # Tunable weights for different indicators
        self.weights = {
            "threat_type": 1.0,        # MAIN: actual detected threats (full weight)
            "ddos_score": 0.3,         # Secondary: DDoS patterns
            "suspicious_ua": 0.2,      # User agent patterns
            "blacklist": 0.4,          # IP reputation
            "payload_analysis": 0.35,  # NEW: Deep payload analysis
            "context_score": 0.25,     # NEW: Contextual scoring
            "pattern_score": 0.4,      # NEW: Pattern matching score
        }
        
        # Enhanced suspicious patterns for URL/payload analysis
        self.sql_patterns = [
            r"(?:union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|update\s+.*\s+set)",
            r"(?:or\s+1\s*=\s*1|and\s+1\s*=\s*1|or\s+'1'\s*=\s*'1'|or\s+\"1\"\s*=\s*\"1\")",
            r"(?:drop\s+table|truncate\s+table|alter\s+table|create\s+table)",
            r"(?:exec\s*\(|execute\s*\(|sp_executesql|xp_cmdshell)",
            r"(?:concat\s*\(|char\s*\(|substring\s*\(|benchmark\s*\()",
            r"(?:sleep\s*\(\s*\d|waitfor\s+delay|pg_sleep)",
            r"(?:information_schema|mysql\.|sys\.)",
            r"(?:load_file|into\s+outfile|into\s+dumpfile)",
        ]
        
        self.xss_patterns = [
            r"<script[^>]*>",
            r"javascript\s*:",
            r"on(?:load|error|click|mouse|focus|blur|submit)\s*=",
            r"<iframe[^>]*>",
            r"<img[^>]*\s+onerror\s*=",
            r"document\.(?:cookie|write|location)",
            r"window\.(?:location|open)",
            r"eval\s*\(",
            r"<svg[^>]*\s+onload\s*=",
            r"data\s*:\s*text/html",
        ]
        
        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e[%/\\]",
            r"/etc/passwd",
            r"/etc/shadow",
            r"c:\\windows",
            r"\\windows\\",
            r"boot\.ini",
            r"win\.ini",
        ]
        
        self.command_injection_patterns = [
            r"[;&|`$]",
            r"\$\([^)]+\)",
            r"`[^`]+`",
            r"(?:ls|cat|id|whoami|pwd|uname)\s",
            r"(?:wget|curl)\s+https?://",
            r"/bin/(?:sh|bash|zsh|ksh)",
            r"nc\s+-[elvp]",
            r"python\s+-c",
            r"perl\s+-e",
        ]
        
        self.ssrf_patterns = [
            r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0)",
            r"(?:169\.254\.\d+\.\d+)",  # AWS metadata
            r"(?:http://\d+\.\d+\.\d+\.\d+)",
            r"(?:file://)",
            r"(?:gopher://)",
            r"(?:dict://)",
        ]
        
        # Scanner/Bot signatures
        self.scanner_signatures = [
            "sqlmap", "nikto", "nessus", "nmap", "masscan", "acunetix",
            "burpsuite", "owasp", "dirbuster", "gobuster", "wfuzz", "hydra",
            "nuclei", "metasploit", "havij", "arachni", "skipfish"
        ]
        
        # Suspicious endpoint patterns
        self.sensitive_endpoints = [
            r"/admin",
            r"/wp-admin",
            r"/login",
            r"/api/v\d+/(?:users|tokens|keys|secrets)",
            r"/\.(?:git|env|htaccess|htpasswd)",
            r"/phpmyadmin",
            r"/config\.",
            r"/backup",
            r"/debug",
            r"/shell",
            r"/cmd",
            r"/exec",
        ]

    def _clamp(self, v: float) -> float:
        return max(0.0, min(1.0, v))

    def _check_patterns(self, text: str, patterns: list) -> tuple:
        """Check text against regex patterns, return (score, matched_patterns)"""
        import re
        if not text:
            return 0.0, []
        
        text_lower = text.lower()
        matches = []
        
        for pattern in patterns:
            try:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    matches.append(pattern[:30])
            except Exception:
                continue
        
        score = min(1.0, len(matches) * 0.3) if matches else 0.0
        return score, matches

    def _analyze_payload(self, url: str, body: str = "", headers: dict = None) -> dict:
        """Deep payload analysis for malicious patterns"""
        full_payload = f"{url} {body}".lower()
        
        analysis = {
            "sql_injection": 0.0,
            "xss": 0.0,
            "path_traversal": 0.0,
            "command_injection": 0.0,
            "ssrf": 0.0,
            "detected_patterns": [],
            "risk_factors": [],
        }
        
        # Check each attack type
        sql_score, sql_matches = self._check_patterns(full_payload, self.sql_patterns)
        if sql_score > 0:
            analysis["sql_injection"] = sql_score
            analysis["detected_patterns"].extend([f"SQL:{m}" for m in sql_matches])
            analysis["risk_factors"].append("sql_patterns_detected")
        
        xss_score, xss_matches = self._check_patterns(full_payload, self.xss_patterns)
        if xss_score > 0:
            analysis["xss"] = xss_score
            analysis["detected_patterns"].extend([f"XSS:{m}" for m in xss_matches])
            analysis["risk_factors"].append("xss_patterns_detected")
        
        path_score, path_matches = self._check_patterns(full_payload, self.path_traversal_patterns)
        if path_score > 0:
            analysis["path_traversal"] = path_score
            analysis["detected_patterns"].extend([f"PATH:{m}" for m in path_matches])
            analysis["risk_factors"].append("path_traversal_detected")
        
        cmd_score, cmd_matches = self._check_patterns(full_payload, self.command_injection_patterns)
        if cmd_score > 0:
            analysis["command_injection"] = cmd_score
            analysis["detected_patterns"].extend([f"CMD:{m}" for m in cmd_matches])
            analysis["risk_factors"].append("command_injection_detected")
        
        ssrf_score, ssrf_matches = self._check_patterns(full_payload, self.ssrf_patterns)
        if ssrf_score > 0:
            analysis["ssrf"] = ssrf_score
            analysis["detected_patterns"].extend([f"SSRF:{m}" for m in ssrf_matches])
            analysis["risk_factors"].append("ssrf_patterns_detected")
        
        # Aggregate score (weighted by severity)
        analysis["total_score"] = self._clamp(
            sql_score * 1.0 +
            xss_score * 0.9 +
            path_score * 0.95 +
            cmd_score * 1.0 +
            ssrf_score * 0.9
        )
        
        return analysis

    def _analyze_user_agent(self, user_agent: str) -> dict:
        """Analyze user agent for suspicious indicators"""
        if not user_agent:
            return {"score": 0.3, "type": "missing", "note": "no_user_agent"}
        
        ua_lower = user_agent.lower()
        
        # Check for known scanners
        for scanner in self.scanner_signatures:
            if scanner in ua_lower:
                return {"score": 0.95, "type": "scanner", "note": f"scanner:{scanner}"}
        
        # Check for automation tools
        automation_tools = ["curl", "wget", "python-requests", "httpx", "axios", "node-fetch", "go-http-client", "java/"]
        for tool in automation_tools:
            if tool in ua_lower:
                return {"score": 0.6, "type": "automation", "note": f"automation:{tool}"}
        
        # Check for bots
        if "bot" in ua_lower or "crawler" in ua_lower or "spider" in ua_lower:
            # Legitimate bots
            legit_bots = ["googlebot", "bingbot", "slurp", "duckduckbot", "baiduspider"]
            for bot in legit_bots:
                if bot in ua_lower:
                    return {"score": 0.1, "type": "legit_bot", "note": f"legitimate:{bot}"}
            return {"score": 0.7, "type": "unknown_bot", "note": "unknown_bot"}
        
        # Empty or very short UA
        if len(user_agent) < 10:
            return {"score": 0.5, "type": "minimal", "note": "minimal_ua"}
        
        return {"score": 0.0, "type": "browser", "note": "normal_browser"}

    def _analyze_context(self, method: str, url: str, headers: dict = None) -> dict:
        """Analyze request context for suspicious behavior"""
        import re
        context = {
            "score": 0.0,
            "risk_factors": [],
            "endpoint_type": "normal",
        }
        
        method = (method or "GET").upper()
        url_lower = (url or "").lower()
        
        # Check sensitive endpoints
        for pattern in self.sensitive_endpoints:
            try:
                if re.search(pattern, url_lower):
                    context["score"] += 0.3
                    context["risk_factors"].append(f"sensitive_endpoint:{pattern[:20]}")
                    context["endpoint_type"] = "sensitive"
            except Exception:
                continue
        
        # Risky method + endpoint combinations
        if method in ["PUT", "DELETE", "PATCH"] and context["endpoint_type"] == "sensitive":
            context["score"] += 0.2
            context["risk_factors"].append("risky_method_on_sensitive")
        
        # POST to unusual endpoints
        if method == "POST" and any(x in url_lower for x in ["/search", "/api/query", "/lookup"]):
            context["score"] += 0.1
            context["risk_factors"].append("post_to_query_endpoint")
        
        # Check for parameter tampering indicators
        if "id=" in url_lower or "user=" in url_lower or "admin=" in url_lower:
            context["score"] += 0.15
            context["risk_factors"].append("sensitive_params")
        
        # Very long query strings
        if "?" in url and len(url.split("?", 1)[1]) > 500:
            context["score"] += 0.2
            context["risk_factors"].append("long_query_string")
        
        context["score"] = self._clamp(context["score"])
        return context

    def _ua_suspicious(self, user_agent: str) -> float:
        """Legacy method for backwards compatibility"""
        ua_analysis = self._analyze_user_agent(user_agent)
        return ua_analysis["score"]

    def score_event(self, event: Any) -> Dict[str, Any]:
        """Enhanced multi-factor security event scoring.

        Returns comprehensive analysis with:
        - ai_score: Overall threat score (0.0-1.0)
        - ai_confidence: Confidence in the assessment
        - analysis: Detailed breakdown of scoring factors
        - risk_factors: List of identified risk indicators
        """
        # Access fields with tolerance for both dataclass and dict
        details = getattr(event, "details", {}) or {}
        ddos_score = float(details.get("ddos_score", 0))
        ua = getattr(event, "user_agent", details.get("user_agent", "")) or ""
        source_ip = getattr(event, "source_ip", details.get("source_ip", "")) or ""
        url = getattr(event, "url", getattr(event, "target_url", "")) or ""
        method = getattr(event, "method", details.get("method", "GET")) or "GET"
        headers = details.get("headers", {})
        body = details.get("body", "")
        
        # Check actual threat type
        threat_type = getattr(event, "threat_type", details.get("threat_type", "none")) or "none"
        was_blocked = getattr(event, "blocked", details.get("blocked", False))
        
        # Initialize analysis results
        all_risk_factors = []
        all_detected_patterns = []
        component_scores = {}
        
        # 1. THREAT TYPE SCORING (Primary indicator)
        threat_score = 0.0
        if threat_type != "none":
            threat_scores = {
                # Injection Attacks (Critical)
                "sql_injection": 1.0,
                "command_injection": 1.0,
                "ldap_injection": 0.95,
                "xml_injection": 0.9,
                "xpath_injection": 0.9,
                "template_injection": 0.95,
                "ssti": 0.95,
                "nosql_injection": 0.95,
                "code_injection": 1.0,
                
                # Cross-Site Attacks (High)
                "xss_attempt": 0.9,
                "stored_xss": 0.95,
                "reflected_xss": 0.85,
                "dom_xss": 0.85,
                "csrf": 0.85,
                "clickjacking": 0.7,
                
                # File & Path Attacks (High)
                "path_traversal": 0.95,
                "directory_traversal": 0.95,
                "lfi": 0.95,
                "rfi": 0.98,
                "file_upload": 0.9,
                "unrestricted_file_upload": 0.95,
                
                # Remote Execution (Critical)
                "rce": 1.0,
                "remote_code_execution": 1.0,
                "deserialization": 0.95,
                "unsafe_deserialization": 0.95,
                
                # Authentication & Session Attacks (High)
                "auth_bypass": 0.95,
                "authentication_bypass": 0.95,
                "session_hijacking": 0.9,
                "session_fixation": 0.85,
                "credential_stuffing": 0.8,
                "brute_force": 0.75,
                "password_spray": 0.75,
                
                # Server Attacks (High)
                "ssrf": 0.95,
                "xxe": 0.95,
                "xml_bomb": 0.9,
                "billion_laughs": 0.9,
                
                # Network & DDoS Attacks (Medium-High)
                "ddos_attack": 0.85,
                "slowloris": 0.8,
                "syn_flood": 0.85,
                "udp_flood": 0.8,
                "http_flood": 0.85,
                "amplification_attack": 0.9,
                
                # Header & Protocol Attacks (Medium)
                "header_injection": 0.8,
                "crlf_injection": 0.8,
                "host_header_injection": 0.85,
                "http_response_splitting": 0.85,
                "http_smuggling": 0.9,
                
                # Information Disclosure (Medium)
                "directory_listing": 0.6,
                "sensitive_data_exposure": 0.7,
                "information_disclosure": 0.65,
                "path_disclosure": 0.6,
                "error_disclosure": 0.5,
                
                # Automated Attacks (Medium)
                "bot_attack": 0.7,
                "web_scraping": 0.5,
                "automated_scan": 0.6,
                "vulnerability_scan": 0.7,
                "scanner_detected": 0.7,
                
                # API & Business Logic (Medium-High)
                "api_abuse": 0.75,
                "excessive_data_exposure": 0.7,
                "broken_authentication": 0.9,
                "broken_access_control": 0.85,
                "mass_assignment": 0.8,
                "security_misconfiguration": 0.7,
                
                # Rate & Resource Abuse (Low-Medium)
                "rate_limit_exceeded": 0.6,
                "resource_exhaustion": 0.75,
                "zip_bomb": 0.8,
                "regex_dos": 0.75,
                
                # Access Control (Medium-High)
                "privilege_escalation": 0.95,
                "idor": 0.85,
                "forced_browsing": 0.7,
                "parameter_tampering": 0.75,
                
                # Other Threats
                "blocked_ip": 0.8,
                "suspicious_behavior": 0.7,
                "malicious_payload": 0.85,
                "backdoor_attempt": 0.95,
                "webshell": 0.98,
                "crypto_mining": 0.9
            }
            threat_score = threat_scores.get(threat_type, 0.5)
            all_risk_factors.append(f"threat_detected:{threat_type}")
        
        component_scores["threat_type"] = threat_score
        
        # 2. PAYLOAD ANALYSIS (Deep pattern matching)
        payload_analysis = self._analyze_payload(url, body)
        payload_score = payload_analysis["total_score"]
        all_detected_patterns.extend(payload_analysis["detected_patterns"])
        all_risk_factors.extend(payload_analysis["risk_factors"])
        component_scores["payload_analysis"] = payload_score
        
        # 3. USER AGENT ANALYSIS
        ua_analysis = self._analyze_user_agent(ua)
        ua_score = ua_analysis["score"]
        if ua_analysis["score"] > 0.3:
            all_risk_factors.append(f"ua:{ua_analysis['note']}")
        component_scores["user_agent"] = ua_score
        
        # 4. CONTEXT ANALYSIS
        context_analysis = self._analyze_context(method, url, headers)
        context_score = context_analysis["score"]
        all_risk_factors.extend(context_analysis["risk_factors"])
        component_scores["context"] = context_score
        
        # 5. DDOS SCORE
        norm_ddos = self._clamp(ddos_score / 10.0)
        if norm_ddos > 0.3:
            all_risk_factors.append(f"ddos_indicator:{ddos_score:.1f}")
        component_scores["ddos"] = norm_ddos
        
        # 6. BLACKLIST CHECK
        blacklisted = 1.0 if details.get("blacklisted") or details.get("reason") == "IP in blocklist" else 0.0
        if blacklisted > 0:
            all_risk_factors.append("ip_blacklisted")
        component_scores["blacklist"] = blacklisted
        
        # 7. CALCULATE FINAL SCORE using weighted combination
        if threat_score > 0:
            # If detected threat, use as base and add modifiers
            secondary_boost = (
                payload_score * 0.15 +
                ua_score * 0.1 +
                context_score * 0.1 +
                norm_ddos * 0.1 +
                blacklisted * 0.15
            )
            final_score = threat_score + (secondary_boost * (1 - threat_score))
        else:
            # No explicit threat - calculate from all indicators
            final_score = (
                payload_score * self.weights["payload_analysis"] +
                ua_score * self.weights["suspicious_ua"] +
                context_score * self.weights["context_score"] +
                norm_ddos * self.weights["ddos_score"] +
                blacklisted * self.weights["blacklist"]
            )
        
        final_score = self._clamp(final_score)
        
        # 8. CALCULATE CONFIDENCE
        # Confidence is higher when we have multiple strong indicators
        indicator_count = sum(1 for s in component_scores.values() if s > 0.3)
        max_component = max(component_scores.values()) if component_scores else 0
        
        if threat_score > 0.7:
            confidence = 0.85 + (0.15 * (indicator_count / 5))
        elif final_score > 0.5:
            confidence = 0.6 + (0.3 * max_component)
        else:
            confidence = 0.4 + (0.4 * max_component)
        
        confidence = self._clamp(confidence)
        
        # 9. DETERMINE SEVERITY LABEL
        if final_score >= 0.9:
            severity = "critical"
        elif final_score >= 0.7:
            severity = "high"
        elif final_score >= 0.5:
            severity = "medium"
        elif final_score >= 0.3:
            severity = "low"
        else:
            severity = "info"
        
        # 10. BUILD NOTE/SUMMARY
        note_parts = []
        if threat_type != "none":
            note_parts.append(f"threat:{threat_type}")
        if was_blocked:
            note_parts.append("BLOCKED")
        if payload_score > 0.3:
            note_parts.append(f"payload:{payload_score:.2f}")
        if ua_score > 0.3:
            note_parts.append(ua_analysis["note"])
        if context_score > 0.3:
            note_parts.append("suspicious_context")
        if norm_ddos > 0.3:
            note_parts.append(f"ddos:{ddos_score:.1f}")
        if blacklisted > 0:
            note_parts.append("blacklisted")
        
        note = ", ".join(note_parts) if note_parts else "no_strong_indicators"

        return {
            "ai_score": round(final_score, 3),
            "ai_confidence": round(confidence, 3),
            "severity": severity,
            "note": note,
            "scorer_type": "heuristic_enhanced",
            "component_scores": {k: round(v, 3) for k, v in component_scores.items()},
            "risk_factors": all_risk_factors[:10],  # Limit to top 10
            "detected_patterns": all_detected_patterns[:10],  # Limit to top 10
            "analysis_version": "2.0"
        }


class ModelScorer:
    """Optional model-backed scorer that can load a saved model (.joblib)
    and produce a `model_score` for an event. This is lightweight and optional
    — if joblib or model file is missing, it becomes a noop.
    """

    def __init__(self, model_path: Optional[str] = None):
        # Use absolute path relative to this file
        if model_path:
            self.model_path = model_path
        else:
            # Default to waf/models/alert_model.joblib
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))  # Go up to waf/ directory
            self.model_path = os.path.join(base_dir, "models", "alert_model.joblib")
        
        self.model = None
        self.embedder = None
        self.embedder_name = None
        self._load_model()

    def _load_model(self):
        if joblib is None:
            print("⚠️ joblib not available - ML model scoring disabled")
            return
        try:
            if not os.path.exists(self.model_path):
                print(f"⚠️ Model file not found: {self.model_path}")
                print("   Run training first: python waf/scripts/train_alert_model.py")
                return
            
            print(f"📦 Loading ML model from: {self.model_path}")
            data = joblib.load(self.model_path)
            # expected structure: {"model": <estimator>, "embedder_name": <str>}
            self.model = data.get("model") if isinstance(data, dict) else data
            self.embedder_name = data.get("embedder_name") if isinstance(data, dict) else None
            
            print(f"✓ Model loaded successfully: {type(self.model).__name__}")
            
            if self.embedder_name and SentenceTransformer is not None:
                try:
                    print(f"📥 Loading embedder: {self.embedder_name}")
                    self.embedder = SentenceTransformer(self.embedder_name)
                    print("✓ Embedder loaded successfully")
                except Exception as e:
                    print(f"⚠️ Failed to load embedder: {e}")
                    self.embedder = None
            elif self.embedder_name:
                print(f"⚠️ sentence-transformers not available - using numeric features only")
        except Exception as e:
            print(f"❌ Failed to load model: {e}")
            self.model = None

    def _sigmoid(self, x: float) -> float:
        try:
            return 1.0 / (1.0 + math.exp(-x))
        except Exception:
            return 0.0

    def _make_features(self, event: Any):
        """Extract features matching the training data format"""
        details = getattr(event, "details", {}) or {}
        
        # Get ddos_score and payload_length (matching training CSV columns)
        ddos_score = details.get("ddos_score", 0)
        
        # payload_length should be the URL length (matching export_training_data.py line 56)
        url = getattr(event, "url", "") or getattr(event, "target_url", "") or ""
        payload_length = len(url)
        
        nums = [float(ddos_score), float(payload_length)]

        # text concat (matching training: url + " " + user_agent)
        user_agent = getattr(event, "user_agent", "") or ""
        text = f"{url} {user_agent}"

        return nums, text

    def score_event_with_model(self, event: Any) -> Optional[Dict[str, Any]]:
        if self.model is None:
            return None

        nums, text = self._make_features(event)

        X = None
        # compute embedding if possible
        if self.embedder is not None and SentenceTransformer is not None:
            try:
                emb = self.embedder.encode([text])[0]
                X = list(emb) + nums
            except Exception:
                X = nums
        else:
            X = nums

        # ensure 2D
        try:
            import numpy as _np
            arr = _np.array(X).reshape(1, -1)
        except Exception:
            arr = None

        try:
            # Supervised with predict_proba
            if hasattr(self.model, "predict_proba") and arr is not None:
                probs = self.model.predict_proba(arr)[0]
                pred = self.model.predict(arr)[0]
                confidence = float(max(probs))

                # Convert numpy types to Python native types
                predicted_label = int(pred) if hasattr(pred, 'item') else int(pred) if isinstance(pred, (int, float)) else pred

                # Map numeric labels to human-friendly severities when applicable
                suggested_severity = None
                try:
                    # If label is numeric, map to default severity names
                    val = int(predicted_label)
                    severity_map = {0: 'low', 1: 'medium', 2: 'high', 3: 'critical'}
                    suggested_severity = severity_map.get(val, str(predicted_label))
                except Exception:
                    suggested_severity = str(predicted_label)

                return {
                    "model_type": "supervised",
                    "predicted_label": predicted_label,
                    "model_confidence": round(confidence, 3),
                    "suggested_severity": suggested_severity
                }

            # IsolationForest or anomaly detector
            if hasattr(self.model, "decision_function") and arr is not None:
                raw = float(self.model.decision_function(arr)[0])
                # transform so higher -> more anomalous
                anomaly_raw = -raw
                score = self._sigmoid(anomaly_raw)
                return {"model_type": "anomaly", "model_score": round(score, 3), "raw_score": round(raw, 5)}

            # fallback: predict
            if hasattr(self.model, "predict") and arr is not None:
                pred = int(self.model.predict(arr)[0])
                return {"model_type": "predict_only", "predicted": pred}

        except Exception:
            return None

        return None


class UnifiedScorer:
    """Unified AI scorer that can switch between different scoring methods.
    
    Supports:
    - Heuristic scoring (fast, rule-based)
    - LM Studio scoring (AI-powered, uses local LLM)
    - Hybrid scoring (combines both methods)
    """
    
    def __init__(self):
        self.heuristic_scorer = HeuristicScorer()
        self.lm_studio_scorer = LMStudioScorer()
        self.model_scorer = ModelScorer()
    
    def get_active_scorer(self) -> str:
        """Get the currently active scorer type"""
        return _scorer_config["active_scorer"].value
    
    def set_active_scorer(self, scorer_type: str) -> dict:
        """Set the active scorer type"""
        return set_active_scorer(scorer_type)
    
    def get_config(self) -> dict:
        """Get full scorer configuration"""
        config = get_scorer_config()
        config["active_scorer"] = config["active_scorer"].value
        config["lm_studio_available"] = self.lm_studio_scorer.is_available
        return config
    
    def check_lm_studio(self) -> bool:
        """Check if LM Studio is available"""
        return self.lm_studio_scorer._check_availability()
    
    def score_event(self, event: Any) -> Dict[str, Any]:
        """Score an event using the currently active scorer"""
        active = _scorer_config["active_scorer"]
        
        if active == ScorerType.HEURISTIC:
            return self._score_heuristic(event)
        elif active == ScorerType.LM_STUDIO:
            return self._score_lm_studio(event)
        elif active == ScorerType.HYBRID:
            return self._score_hybrid(event)
        else:
            return self._score_heuristic(event)
    
    async def score_event_async(self, event: Any) -> Dict[str, Any]:
        """Asynchronously score an event using the currently active scorer"""
        active = _scorer_config["active_scorer"]
        
        if active == ScorerType.HEURISTIC:
            return self._score_heuristic(event)
        elif active == ScorerType.LM_STUDIO:
            return await self._score_lm_studio_async(event)
        elif active == ScorerType.HYBRID:
            return await self._score_hybrid_async(event)
        else:
            return self._score_heuristic(event)
    
    def _score_heuristic(self, event: Any) -> Dict[str, Any]:
        """Score using heuristic method"""
        result = self.heuristic_scorer.score_event(event)
        
        # Add model scoring if available
        model_result = self.model_scorer.score_event_with_model(event)
        if model_result:
            result["model"] = model_result
        
        return result
    
    def _score_lm_studio(self, event: Any) -> Dict[str, Any]:
        """Score using LM Studio (non-blocking - returns heuristic immediately, LM Studio runs in background)"""
        # Always return heuristic result immediately for fast response
        result = self.heuristic_scorer.score_event(event)
        result["scorer_type"] = "lm_studio_pending"
        result["lm_studio_status"] = "background_processing"
        
        # LM Studio analysis would run async in background if needed
        # For now, just mark that LM Studio mode is active but using fast heuristic
        
        # Add model scoring if available
        model_result = self.model_scorer.score_event_with_model(event)
        if model_result:
            result["model"] = model_result
        
        return result
    
    async def _score_lm_studio_async(self, event: Any) -> Dict[str, Any]:
        """Score using LM Studio (asynchronous)"""
        result = await self.lm_studio_scorer.score_event_async(event)
        
        # Add model scoring if available
        model_result = self.model_scorer.score_event_with_model(event)
        if model_result:
            result["model"] = model_result
        
        return result
    
    def _score_hybrid(self, event: Any) -> Dict[str, Any]:
        """Score using heuristic (fast) - LM Studio runs in background for hybrid mode"""
        # Always use fast heuristic for real-time response
        result = self.heuristic_scorer.score_event(event)
        result["scorer_type"] = "hybrid"
        result["lm_studio_status"] = "background_processing"
        
        # Add model scoring if available
        model_result = self.model_scorer.score_event_with_model(event)
        if model_result:
            result["model"] = model_result
        
        return result
    
    async def _score_hybrid_async(self, event: Any) -> Dict[str, Any]:
        """Score using both methods and combine results (asynchronous)"""
        heuristic_result = self.heuristic_scorer.score_event(event)
        lm_result = await self.lm_studio_scorer.score_event_async(event)
        
        return self._combine_scores(heuristic_result, lm_result, event)
    
    def _combine_scores(self, heuristic: Dict, lm_studio: Dict, event: Any) -> Dict[str, Any]:
        """Combine scores from heuristic and LM Studio methods"""
        h_score = heuristic.get("ai_score", 0.5)
        h_conf = heuristic.get("ai_confidence", 0.5)
        
        l_score = lm_studio.get("ai_score", 0.5)
        l_conf = lm_studio.get("ai_confidence", 0.5)
        
        # Use LM Studio if it successfully analyzed, otherwise weight heuristic more
        if lm_studio.get("scorer_type") == "lm_studio":
            w_h = _scorer_config["hybrid_weight_heuristic"]
            w_l = _scorer_config["hybrid_weight_lm_studio"]
        else:
            # Fallback: weight heuristic more heavily
            w_h = 0.8
            w_l = 0.2
        
        combined_score = (h_score * w_h) + (l_score * w_l)
        combined_conf = (h_conf * w_h) + (l_conf * w_l)
        
        result = {
            "ai_score": round(combined_score, 3),
            "ai_confidence": round(combined_conf, 3),
            "note": f"hybrid({heuristic.get('note', '')[:30]}|{lm_studio.get('note', '')[:30]})",
            "scorer_type": "hybrid",
            "heuristic_score": h_score,
            "lm_studio_score": l_score,
            "weights": {"heuristic": w_h, "lm_studio": w_l}
        }
        
        # Add LLM analysis if available
        if lm_studio.get("llm_analysis"):
            result["llm_analysis"] = lm_studio["llm_analysis"]
            result["llm_severity"] = lm_studio.get("llm_severity")
        
        # Add model scoring if available
        model_result = self.model_scorer.score_event_with_model(event)
        if model_result:
            result["model"] = model_result
        
        return result


# Create singleton instances for easy access
_unified_scorer = None

def get_unified_scorer() -> UnifiedScorer:
    """Get the singleton UnifiedScorer instance"""
    global _unified_scorer
    if _unified_scorer is None:
        _unified_scorer = UnifiedScorer()
    return _unified_scorer
