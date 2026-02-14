"""
Raw text log parser - best-effort extraction from unstructured text.
"""
import re
from datetime import datetime


class RawLogParser:
    """Parse unstructured text log into canonical fields via regex heuristics."""

    IP_RE = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    HTTP_METHOD_RE = re.compile(r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\b', re.I)
    HTTP_PATH_RE = re.compile(r'(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)', re.I)
    STATUS_CODE_RE = re.compile(r'\b([1-5]\d{2})\b')
    PORT_RE = re.compile(r':(\d{2,5})\b')

    ACTION_PATTERNS = {
        "BLOCKED": re.compile(r'\b(block|blocked|deny|denied|reject|rejected|drop|dropped)\b', re.I),
        "ALLOWED": re.compile(r'\b(allow|allowed|permit|permitted|pass|accept|accepted)\b', re.I),
        "RATE_LIMITED": re.compile(r'\b(rate.?limit|throttle|throttled)\b', re.I),
    }

    ATTACK_PATTERNS = {
        "SQLI": re.compile(r'\b(sql.?inject|sqli|union.?select|or.?1\s*=\s*1)\b', re.I),
        "XSS": re.compile(r'\b(xss|cross.?site.?script|<script)\b', re.I),
        "RCE": re.compile(r'\b(rce|remote.?code|command.?exec|cmd.?inject)\b', re.I),
        "LFI": re.compile(r'\b(lfi|local.?file|path.?traversal|\.\.\/)\b', re.I),
        "BRUTE_FORCE": re.compile(r'\b(brute.?force|login.?fail|auth.?fail)\b', re.I),
        "PORT_SCAN": re.compile(r'\b(port.?scan|nmap|syn.?scan)\b', re.I),
        "DDOS": re.compile(r'\b(ddos|flood|volumetric)\b', re.I),
        "BOT": re.compile(r'\b(bot|crawler|spider|scraper)\b', re.I),
    }

    def parse(self, raw: str) -> dict:
        """Best-effort parse of a raw text log line."""
        result = {
            "raw_log": raw,
            "timestamp": datetime.utcnow(),
            "ingestion_pipeline": "raw_text",
        }

        # Extract IPs
        ips = self.IP_RE.findall(raw)
        if ips:
            result["src_ip"] = ips[0]
            if len(ips) > 1:
                result["dst_ip"] = ips[1]
        else:
            result["src_ip"] = "0.0.0.0"

        # HTTP method
        method_match = self.HTTP_METHOD_RE.search(raw)
        if method_match:
            result["http_method"] = method_match.group(1).upper()

        # HTTP path
        path_match = self.HTTP_PATH_RE.search(raw)
        if path_match:
            result["http_path"] = path_match.group(1)

        # Status code
        status_match = self.STATUS_CODE_RE.search(raw)
        if status_match:
            result["http_status"] = int(status_match.group(1))

        # Action detection
        for action, pattern in self.ACTION_PATTERNS.items():
            if pattern.search(raw):
                result["action"] = action
                break
        else:
            result["action"] = "ALLOWED"

        # Attack type detection
        for attack, pattern in self.ATTACK_PATTERNS.items():
            if pattern.search(raw):
                result["attack_type"] = attack
                result["severity"] = "HIGH" if attack in ("SQLI", "RCE", "LFI") else "MEDIUM"
                break
        else:
            result["attack_type"] = "NONE"
            result["severity"] = "INFO"

        return result
