"""
Tests for the ThreatLoom ingestion engine and parsers.
"""
import pytest
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# JSON Parser Tests
# ---------------------------------------------------------------------------
class TestJSONParser:
    """Tests for threatloom.ingestion.parsers.json_parser.JSONLogParser"""

    def setup_method(self):
        from threatloom.ingestion.parsers.json_parser import JSONLogParser
        self.parser = JSONLogParser()

    def test_basic_json_parse(self):
        raw = '{"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1", "action": "BLOCKED"}'
        result = self.parser.parse(raw)
        assert result is not None
        assert result["src_ip"] == "10.0.0.1"
        assert result["dst_ip"] == "192.168.1.1"
        assert result["action"] == "BLOCKED"

    def test_field_aliases(self):
        """source_ip should map to src_ip, destination_ip to dst_ip, etc."""
        raw = '{"source_ip": "1.2.3.4", "destination_ip": "5.6.7.8", "source_port": 443}'
        result = self.parser.parse(raw)
        assert result["src_ip"] == "1.2.3.4"
        assert result["dst_ip"] == "5.6.7.8"
        assert result["src_port"] == 443

    def test_http_fields(self):
        raw = '{"src_ip": "10.0.0.1", "method": "POST", "path": "/api/login", "status_code": 403}'
        result = self.parser.parse(raw)
        assert result["http_method"] == "POST"
        assert result["http_path"] == "/api/login"
        assert result["http_status"] == 403

    def test_invalid_json(self):
        result = self.parser.parse("this is not json at all")
        assert result is None

    def test_empty_json(self):
        result = self.parser.parse("{}")
        assert result is not None  # valid JSON, returns empty dict

    def test_nested_attack_info(self):
        raw = '{"src_ip": "10.0.0.1", "attack": {"type": "SQLI", "severity": "HIGH"}}'
        result = self.parser.parse(raw)
        assert result is not None

    def test_dict_input(self):
        data = {"src_ip": "10.0.0.1", "action": "ALLOWED", "http_method": "GET"}
        result = self.parser.parse(data)
        assert result["src_ip"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# Syslog Parser Tests
# ---------------------------------------------------------------------------
class TestSyslogParser:
    """Tests for threatloom.ingestion.parsers.syslog_parser.SyslogParser"""

    def setup_method(self):
        from threatloom.ingestion.parsers.syslog_parser import SyslogParser
        self.parser = SyslogParser()

    def test_rfc3164_format(self):
        line = '<134>Jan  5 14:23:01 firewall01 WAF: action=BLOCKED src_ip=192.168.1.100 dst_ip=10.0.0.5 attack_type=SQLI'
        result = self.parser.parse(line)
        assert result is not None
        assert result.get("src_ip") == "192.168.1.100"

    def test_kv_extraction(self):
        line = '<134>Jan  5 14:23:01 fw1 WAF: src_ip=1.2.3.4 action=BLOCKED http_method=POST path=/login'
        result = self.parser.parse(line)
        assert result is not None
        assert result.get("src_ip") == "1.2.3.4"

    def test_plain_kv(self):
        """Should handle plain key=value without syslog header"""
        line = 'src_ip=10.0.0.1 action=ALLOWED dst_ip=192.168.1.1'
        result = self.parser.parse(line)
        assert result is not None

    def test_empty_input(self):
        result = self.parser.parse("")
        assert result is None or result == {}


# ---------------------------------------------------------------------------
# Raw Parser Tests
# ---------------------------------------------------------------------------
class TestRawParser:
    """Tests for threatloom.ingestion.parsers.raw_parser.RawLogParser"""

    def setup_method(self):
        from threatloom.ingestion.parsers.raw_parser import RawLogParser
        self.parser = RawLogParser()

    def test_ip_extraction(self):
        line = "Connection from 192.168.1.50 to 10.0.0.1 port 443 BLOCKED"
        result = self.parser.parse(line)
        assert result is not None
        assert "src_ip" in result or "raw_message" in result

    def test_http_method_extraction(self):
        line = 'GET /api/users HTTP/1.1 from 10.0.0.1 - 200 OK'
        result = self.parser.parse(line)
        assert result is not None

    def test_action_keywords(self):
        for action in ["BLOCKED", "ALLOWED", "DROPPED", "RATE_LIMITED"]:
            line = f"10.0.0.1 {action} request to /admin"
            result = self.parser.parse(line)
            assert result is not None

    def test_empty_line(self):
        result = self.parser.parse("")
        assert result is None or result.get("raw_message") == ""


# ---------------------------------------------------------------------------
# Normalizer Tests
# ---------------------------------------------------------------------------
class TestLogNormalizer:
    """Tests for threatloom.ingestion.normalizer.LogNormalizer"""

    def setup_method(self):
        from threatloom.ingestion.normalizer import LogNormalizer
        self.normalizer = LogNormalizer()

    def test_basic_normalization(self):
        data = {
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.1",
            "action": "BLOCKED",
            "http_method": "POST",
            "http_path": "/api/data",
            "http_status": 403,
        }
        result = self.normalizer.normalize(data)
        assert result["src_ip"] == "10.0.0.1"
        assert result["action"] == "BLOCKED"

    def test_port_clamping(self):
        data = {"src_ip": "10.0.0.1", "src_port": 99999}
        result = self.normalizer.normalize(data)
        assert result["src_port"] <= 65535

    def test_long_path_truncation(self):
        data = {"src_ip": "10.0.0.1", "http_path": "/" + "a" * 5000}
        result = self.normalizer.normalize(data)
        assert len(result.get("http_path", "")) <= 2048

    def test_missing_src_ip_default(self):
        data = {"action": "ALLOWED"}
        result = self.normalizer.normalize(data)
        assert "src_ip" in result  # should default to something


# ---------------------------------------------------------------------------
# Ingestion Engine Integration Tests
# ---------------------------------------------------------------------------
class TestIngestionEngine:
    """Tests for threatloom.ingestion.engine.IngestionEngine"""

    def test_engine_instantiation(self):
        from threatloom.ingestion.engine import IngestionEngine
        engine = IngestionEngine()
        assert engine is not None

    def test_parse_json(self):
        from threatloom.ingestion.engine import IngestionEngine
        engine = IngestionEngine()
        data = {"src_ip": "10.0.0.1", "action": "BLOCKED", "attack_type": "SQLI"}
        parsed = engine.parse("json", data)
        assert parsed is not None

    def test_parse_invalid_format(self):
        from threatloom.ingestion.engine import IngestionEngine
        engine = IngestionEngine()
        parsed = engine.parse("xml", "<data/>")
        assert parsed is None  # unsupported format


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
