"""
Core WAF Engine - Main processing engine for the Web Application Firewall
Handles request/response processing, security checks, and threat detection
"""

import os
import time
import asyncio
import re
import sqlite3
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import ipaddress
import structlog

from ..config import get_settings
from .security_manager import SecurityManager
from .ai_scoring import HeuristicScorer, ModelScorer, get_unified_scorer


logger = structlog.get_logger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionType(Enum):
    """Actions that can be taken on requests"""
    ALLOW = "allow"
    BLOCK = "block"
    CHALLENGE = "challenge"
    LOG = "log"
    RATE_LIMIT = "rate_limit"


@dataclass
class SecurityEvent:
    """Security event data structure"""
    id: str
    timestamp: datetime
    threat_type: str
    threat_level: ThreatLevel
    source_ip: str
    target_url: str
    user_agent: str
    action_taken: ActionType
    details: Dict[str, Any] = field(default_factory=dict)
    blocked: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert security event to dictionary"""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "threat_type": self.threat_type,
            "threat_level": self.threat_level.value,
            "source_ip": self.source_ip,
            "target_url": self.target_url,
            "user_agent": self.user_agent,
            "action_taken": self.action_taken.value,
            "details": self.details,
            "blocked": self.blocked,
        }


@dataclass
class RequestMetrics:
    """Request processing metrics"""
    total_requests: int = 0
    blocked_requests: int = 0
    allowed_requests: int = 0
    threats_detected: int = 0
    avg_response_time: float = 0.0
    incoming_bytes: int = 0
    outgoing_bytes: int = 0
    last_reset: datetime = field(default_factory=datetime.now)

    @property
    def uptime_seconds(self) -> float:
        """Return the number of seconds since the metrics were last reset."""
        return max(0.0, (datetime.now() - self.last_reset).total_seconds())
    
    def reset(self):
        """Reset metrics"""
        self.total_requests = 0
        self.blocked_requests = 0
        self.allowed_requests = 0
        self.threats_detected = 0
        self.avg_response_time = 0.0
        self.incoming_bytes = 0
        self.outgoing_bytes = 0
        self.last_reset = datetime.now()


class WAFEngine:
    """
    Main WAF Engine for processing HTTP requests and responses
    Implements security checks, threat detection, and request filtering
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.started_at = datetime.now()
        self.security_manager = SecurityManager()
        # Unified AI scorer with switching capability (heuristic/LM Studio/hybrid)
        try:
            self.ai_scorer = get_unified_scorer()
        except Exception:
            self.ai_scorer = None
        try:
            self.model_scorer = ModelScorer()
        except Exception:
            self.model_scorer = None
        try:
            from services.threatloom_integration import ThreatLoomIntegrator
            self.threatloom_integrator = ThreatLoomIntegrator(
                api_url=self.settings.threatloom_api_url,
                api_key=self.settings.threatloom_api_key,
                enabled=self.settings.threatloom_enabled,
            )
        except Exception as exc:
            self.threatloom_integrator = None
            print(f"⚠️ ThreatLoom integration not available: {exc}")
        self.metrics = RequestMetrics()
        self.blocked_ips: Dict[str, datetime] = {}
        self.rate_limits: Dict[str, List[datetime]] = {}
        self.security_events: List[SecurityEvent] = []
        print(f"🔧 WAF Engine initialized! Instance ID: {id(self)}, Metrics ID: {id(self.metrics)}")
        
        # Windows Defender Integration
        try:
            from services.windows_defender_integration import get_defender_integration
            self.defender_integration = get_defender_integration()
            self.defender_integration.log_waf_started()
            print("🛡️ Windows Defender integration enabled!")
        except Exception as e:
            self.defender_integration = None
            print(f"⚠️ Windows Defender integration not available: {e}")
        
        # Use absolute path for database
        self.db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "vulnerable.db")
        print(f"📁 WAF Database: {self.db_path}")
        
        # Advanced DDoS tracking
        self.connection_table: Dict[str, Dict[str, Any]] = {}  # IP -> connection data
        self.request_patterns: Dict[str, List[str]] = {}  # IP -> URL patterns
        self.user_agent_cache: Dict[str, int] = {}  # User-Agent -> count
        
        self._init_database()
        self._init_security_patterns()
        
        logger.info("WAF Engine initialized", 
                   engine_version="1.0.0",
                   security_features_enabled=self._get_enabled_features())
    
    def _init_security_patterns(self):
        """Initialize security detection patterns"""
        self.sql_injection_patterns = [
            # ============= BASIC SQL COMMANDS =============
            re.compile(r"union[\s\+\/\*!]*select", re.IGNORECASE),
            re.compile(r"union[\s\+\/\*!]*all[\s\+\/\*!]*select", re.IGNORECASE),
            re.compile(r"drop[\s\+\/\*!]*table", re.IGNORECASE),
            re.compile(r"drop[\s\+\/\*!]*database", re.IGNORECASE),
            re.compile(r"truncate[\s\+\/\*!]*table", re.IGNORECASE),
            re.compile(r"exec[\s\+\/\*!]*(sp_|xp_)", re.IGNORECASE),
            re.compile(r"insert[\s\+\/\*!]*into", re.IGNORECASE),
            re.compile(r"delete[\s\+\/\*!]*from", re.IGNORECASE),
            re.compile(r"update[\s\+\/\*!]*\w+[\s\+\/\*!]*set", re.IGNORECASE),
            re.compile(r"alter[\s\+\/\*!]*table", re.IGNORECASE),
            re.compile(r"create[\s\+\/\*!]*(table|database|procedure|function)", re.IGNORECASE),
            
            # ============= BOOLEAN-BASED BLIND INJECTION =============
            re.compile(r"(\'|\")(\s|%20|\/\*.*?\*\/)*(or|and)(\s|%20|\/\*.*?\*\/)*(\1|%27|%22)", re.IGNORECASE),
            re.compile(r"'\s*(or|and)\s*\d+\s*[=<>!]+\s*\d+", re.IGNORECASE),  # ' OR 1=1, ' AND 1<2
            re.compile(r"'\s*(or|and)\s*'[^']*'\s*[=<>!]+\s*'", re.IGNORECASE),  # ' OR 'a'='a
            re.compile(r"\d+\s*(or|and)\s*\d+\s*[=<>!]", re.IGNORECASE),  # 1 OR 1=1
            re.compile(r"'\s*(or|and)(\s+|$|%20|')", re.IGNORECASE),  # ' OR or ' AND followed by space, end, or quote
            re.compile(r"(or|and)\s*'", re.IGNORECASE),  # OR ' or AND ' (reversed)
            re.compile(r"'\s*(or|and)\s*true", re.IGNORECASE),  # ' OR true
            re.compile(r"'\s*(or|and)\s*false", re.IGNORECASE),  # ' AND false
            re.compile(r"'\s*(or|and)\s*not\s*", re.IGNORECASE),  # ' OR NOT
            re.compile(r"\d+\s*between\s*\d+\s*and\s*\d+", re.IGNORECASE),  # 1 BETWEEN 1 AND 10
            re.compile(r"'\s*is\s*(not\s*)?null", re.IGNORECASE),  # ' IS NULL, ' IS NOT NULL
            re.compile(r"null\s*is\s*(not\s*)?null", re.IGNORECASE),  # NULL IS NULL
            
            # ============= SQL COMMENTS & OBFUSCATION =============
            re.compile(r"--", re.IGNORECASE),  # SQL comment -- (bare double dash)
            re.compile(r"#\s*$", re.IGNORECASE),  # MySQL comment # at end
            re.compile(r"#\s+", re.IGNORECASE),  # MySQL comment # with space
            re.compile(r"/\*[\s\S]*?\*/[\s]*(union|select|from|where|or|and)", re.IGNORECASE),  # SQL block comment with SQL keyword
            re.compile(r"/\*![0-9]*", re.IGNORECASE),  # MySQL conditional comments /*! */
            re.compile(r";%00", re.IGNORECASE),  # Null byte injection
            re.compile(r"(union|select|insert|delete)[\s\S]*?%00", re.IGNORECASE),  # Null byte with SQL keyword
            re.compile(r"[;'\"]\s*--[\s]", re.IGNORECASE),  # Quote/semicolon followed by SQL comment with space
            re.compile(r"--\s*-", re.IGNORECASE),  # -- -
            re.compile(r"--\+", re.IGNORECASE),  # --+
            re.compile(r"--%20", re.IGNORECASE),  # -- with URL encoded space
            
            # ============= ADVANCED STACKED QUERIES =============
            re.compile(r";[\s\+\/\*!]*(drop|delete|truncate|alter|create|insert|update|exec)", re.IGNORECASE),
            re.compile(r"(union|select|insert|update|delete|drop|create|alter|exec|execute)[\s\+]*\/\*.*?\*\/[\s\+]*(select|from|where|union)", re.IGNORECASE),
            re.compile(r"(select|union)[\s\S]{0,100}?(from|into)", re.IGNORECASE),
            re.compile(r"(exec|execute)[\s\+\/\*!]*\(", re.IGNORECASE),
            re.compile(r"(exec|execute)[\s\+\/\*!]*(xp_|sp_)", re.IGNORECASE),
            re.compile(r";\s*declare\s+", re.IGNORECASE),  # ; DECLARE
            
            # ============= TIME-BASED BLIND INJECTION =============
            re.compile(r"(sleep|benchmark|waitfor|pg_sleep|dbms_lock\.sleep)[\s\+\/\*!]*\(", re.IGNORECASE),
            re.compile(r"waitfor[\s\+\/\*!]*delay", re.IGNORECASE),
            re.compile(r"benchmark[\s\+\/\*!]*\([\s\S]*?,[\s\S]*?\)", re.IGNORECASE),  # BENCHMARK(count, expr)
            re.compile(r"sleep[\s\+\/\*!]*\([0-9]+\)", re.IGNORECASE),  # SLEEP(5)
            re.compile(r"pg_sleep[\s\+\/\*!]*\([0-9]+\)", re.IGNORECASE),  # PG_SLEEP(5)
            
            # ============= STRING MANIPULATION & ENCODING (SQL-specific) =============
            re.compile(r"\b(concat|chr|substring|substr|ascii|hex|unhex|bin|oct)[\s\+\/\*!]*\(", re.IGNORECASE),  # SQL functions
            re.compile(r"\bchar[\s\+\/\*!]*\([\s]*[0-9]+[\s]*[,\)]", re.IGNORECASE),  # CHAR(65) or CHAR(65,66) - SQL specific
            re.compile(r"0x[0-9a-f]{6,}", re.IGNORECASE),  # Hex encoding (at least 6 chars for SQL strings)
            re.compile(r"\bconcat_ws[\s\+\/\*!]*\(", re.IGNORECASE),  # CONCAT_WS
            re.compile(r"\bgroup_concat[\s\+\/\*!]*\(", re.IGNORECASE),  # GROUP_CONCAT
            re.compile(r"\bmake_set[\s\+\/\*!]*\(", re.IGNORECASE),  # MAKE_SET
            re.compile(r"['\"][\s]*\|\|[\s]*['\"]", re.IGNORECASE),  # String concatenation '||' between quotes
            
            # ============= DATABASE FINGERPRINTING =============
            re.compile(r"@@(version|servername|hostname|datadir|basedir)", re.IGNORECASE),
            re.compile(r"(version|database|user|current_user|session_user|system_user)[\s\+\/\*!]*\(\)", re.IGNORECASE),
            re.compile(r"information_schema\.", re.IGNORECASE),
            re.compile(r"(pg_|mysql\.|msdb\.|sys\.|sysobjects|syscolumns)", re.IGNORECASE),
            re.compile(r"sqlite_(version|master)", re.IGNORECASE),
            re.compile(r"(master|tempdb|model|msdb)\.", re.IGNORECASE),  # SQL Server databases
            re.compile(r"dual[\s\+]*from", re.IGNORECASE),  # Oracle DUAL table
            re.compile(r"all_tables|all_users|dba_", re.IGNORECASE),  # Oracle system views
            
            # ============= SUBQUERIES & NESTED QUERIES =============
            re.compile(r"\([\s\+\/\*!]*select[\s\S]{0,200}?from", re.IGNORECASE),
            re.compile(r"exists[\s\+\/\*!]*\([\s\+\/\*!]*select", re.IGNORECASE),  # EXISTS (SELECT
            re.compile(r"(any|all|some)[\s\+\/\*!]*\([\s\+\/\*!]*select", re.IGNORECASE),  # ANY (SELECT
            
            # ============= UNION-BASED WITH EVASION =============
            re.compile(r"union[\s\+\/\*!]{1,}(all[\s\+\/\*!]{1,})?select[\s\S]{0,100}?(null|[0-9])", re.IGNORECASE),
            re.compile(r"union[\s\+\/\*!]{1,}select[\s\+\/\*!]{1,}(null|[0-9])", re.IGNORECASE),
            re.compile(r"-[0-9]+[\s\+]*union[\s\+]*select", re.IGNORECASE),  # -1 UNION SELECT
            re.compile(r"order[\s\+\/\*!]*by[\s\+\/\*!]*[0-9]+[\s\+]*--", re.IGNORECASE),  # Column enumeration
            
            # ============= SQL OPERATORS & COMPARISONS =============
            re.compile(r"(&&|\|\||xor)", re.IGNORECASE),  # Logical operators
            re.compile(r"'\s*(=|<|>|!=|<>|<=|>=|like|rlike|regexp)\s*'", re.IGNORECASE),
            re.compile(r"[0-9]+\s*(=|<|>|!=|<>)\s*[0-9]+", re.IGNORECASE),  # Numeric comparisons
            re.compile(r"(div|mod)[\s\+\/\*!]+[0-9]", re.IGNORECASE),  # DIV, MOD operators
            
            # CASE WHEN statements (for blind injection)
            re.compile(r"case\s+when", re.IGNORECASE),
            
            # SQL wildcards and LIKE operators
            re.compile(r"'\s*like\s*'", re.IGNORECASE),
            re.compile(r"%'\s*(or|and)", re.IGNORECASE),
            
            # Backtick injection (MySQL identifier quotes) - ONLY in SQL context
            re.compile(r"`[\w]+`[\s]*(=|like|from|where|select|union)", re.IGNORECASE),  # Backtick with SQL keywords
            
            # ORDER BY clause (used for column enumeration)
            re.compile(r"order\s+by\s+\d+", re.IGNORECASE),  # ORDER BY 1, ORDER BY 28, etc.
            re.compile(r"order\s+by\s+[a-z_]+", re.IGNORECASE),  # ORDER BY column_name
            
            # Common SQL comment patterns with various formats
            re.compile(r"--\s*-", re.IGNORECASE),  # -- -
            re.compile(r"--\s*$", re.IGNORECASE),  # -- at end
            re.compile(r"--\+", re.IGNORECASE),  # --+
            re.compile(r"--%20", re.IGNORECASE),  # -- with space encoded
            
            # Quote followed by OR/AND with SQL logic (more specific to avoid XSS false positives)
            re.compile(r"'\s*(or|and)\s*['\"]?\s*[0-9]+\s*[=<>]", re.IGNORECASE),  # ' OR 1=1, ' AND 2>1
            re.compile(r"'\s*(or|and)\s*['\"]?[a-z0-9_]+['\"]?\s*=\s*['\"]?[a-z0-9_]+", re.IGNORECASE),  # ' OR 'a'='a'
            re.compile(r"'\s+(or|and)\s+\d+\s*(--|#)", re.IGNORECASE),  # ' OR 1 -- or ' OR 1 #
            re.compile(r'"\s*(or|and)\s*["\']?\s*[0-9]+\s*[=<>]', re.IGNORECASE),  # " OR 1=1 with double quotes
            
            # Advanced SQL injection techniques
            re.compile(r"group\s+by\s+", re.IGNORECASE),  # GROUP BY
            re.compile(r"having\s+", re.IGNORECASE),  # HAVING clause
            re.compile(r"limit\s+\d+", re.IGNORECASE),  # LIMIT clause
            re.compile(r"offset\s+\d+", re.IGNORECASE),  # OFFSET clause
            re.compile(r"procedure\s+", re.IGNORECASE),  # PROCEDURE
            re.compile(r"handler\s+", re.IGNORECASE),  # HANDLER
            re.compile(r"declare\s+", re.IGNORECASE),  # DECLARE
            re.compile(r"cursor\s+", re.IGNORECASE),  # CURSOR
            re.compile(r"fetch\s+", re.IGNORECASE),  # FETCH
            re.compile(r"open\s+", re.IGNORECASE),  # OPEN cursor
            re.compile(r"prepare\s+", re.IGNORECASE),  # PREPARE statement
            re.compile(r"execute\s+immediate", re.IGNORECASE),  # EXECUTE IMMEDIATE
            
            # Boolean-based blind variations
            re.compile(r"\d+\s*=\s*\d+", re.IGNORECASE),  # 1=1, 0=0
            re.compile(r"true|false", re.IGNORECASE),  # Boolean literals
            re.compile(r"null\s+is\s+null", re.IGNORECASE),  # NULL IS NULL
            
            # String manipulation functions
            re.compile(r"cast\s*\(", re.IGNORECASE),  # CAST()
            re.compile(r"convert\s*\(", re.IGNORECASE),  # CONVERT()
            re.compile(r"substr\s*\(", re.IGNORECASE),  # SUBSTR()
            re.compile(r"length\s*\(", re.IGNORECASE),  # LENGTH()
            re.compile(r"replace\s*\(", re.IGNORECASE),  # REPLACE()
            re.compile(r"reverse\s*\(", re.IGNORECASE),  # REVERSE()
            re.compile(r"lower\s*\(", re.IGNORECASE),  # LOWER()
            re.compile(r"upper\s*\(", re.IGNORECASE),  # UPPER()
            
            # Database fingerprinting
            re.compile(r"sqlite_version", re.IGNORECASE),  # SQLite version
            re.compile(r"mysql\.", re.IGNORECASE),  # MySQL tables
            re.compile(r"pg_catalog", re.IGNORECASE),  # PostgreSQL catalog
            re.compile(r"sys\.", re.IGNORECASE),  # System tables
            re.compile(r"master\.", re.IGNORECASE),  # SQL Server master db
            
            # Out-of-band techniques
            re.compile(r"load_file\s*\(", re.IGNORECASE),  # LOAD_FILE()
            re.compile(r"into\s+outfile", re.IGNORECASE),  # INTO OUTFILE
            re.compile(r"into\s+dumpfile", re.IGNORECASE),  # INTO DUMPFILE
            re.compile(r"xp_cmdshell", re.IGNORECASE),  # SQL Server command execution
            
            # Second-order injection patterns
            re.compile(r"insert\s+.*?values\s*\(", re.IGNORECASE),  # INSERT with VALUES
            re.compile(r"update\s+.*?set\s+", re.IGNORECASE),  # UPDATE with SET
            
            # NoSQL injection patterns
            re.compile(r"\$ne\s*:", re.IGNORECASE),  # MongoDB $ne
            re.compile(r"\$gt\s*:", re.IGNORECASE),  # MongoDB $gt
            re.compile(r"\$lt\s*:", re.IGNORECASE),  # MongoDB $lt
            
            # ============= WAF BYPASS & EVASION TECHNIQUES =============
            re.compile(r"un(io|on)n[\s\+\/\*!]*(se|le)lect", re.IGNORECASE),  # UNiON SeLECT variations
            re.compile(r"[uU]%6e[iI]%6f[nN]", re.IGNORECASE),  # URL encoded UNION
            re.compile(r"[sS]%65[lL]%65[cC]%74", re.IGNORECASE),  # URL encoded SELECT
            re.compile(r"&#[xX]?[0-9a-fA-F]+;", re.IGNORECASE),  # HTML entity encoding
            re.compile(r"\\u00[0-9a-fA-F]{2}", re.IGNORECASE),  # Unicode escape sequences
            re.compile(r"%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}", re.IGNORECASE),  # Double URL encoding
            re.compile(r"[\+\s]{2,}(union|select|from|where)", re.IGNORECASE),  # Multiple spaces
            
            # ============= ADVANCED ERROR-BASED INJECTION =============
            re.compile(r"extractvalue[\s\+\/\*!]*\(", re.IGNORECASE),  # MySQL EXTRACTVALUE()
            re.compile(r"updatexml[\s\+\/\*!]*\(", re.IGNORECASE),  # MySQL UPDATEXML()
            re.compile(r"exp[\s\+\/\*!]*\(~[\s\+]*\(", re.IGNORECASE),  # MySQL EXP overflow
            re.compile(r"polygon[\s\+\/\*!]*\(", re.IGNORECASE),  # MySQL POLYGON()
            re.compile(r"multipoint[\s\+\/\*!]*\(", re.IGNORECASE),  # MySQL MULTIPOINT()
            re.compile(r"geometrycollection[\s\+\/\*!]*\(", re.IGNORECASE),  # MySQL GEOMETRYCOLLECTION()
            re.compile(r"linestring[\s\+\/\*!]*\(", re.IGNORECASE),  # MySQL LINESTRING()
            re.compile(r"multilinestring[\s\+\/\*!]*\(", re.IGNORECASE),  # MySQL MULTILINESTRING()
            re.compile(r"multipolygon[\s\+\/\*!]*\(", re.IGNORECASE),  # MySQL MULTIPOLYGON()
            re.compile(r"convert[\s\+]*\([\s\S]*?,[\s\S]*?\)", re.IGNORECASE),  # CONVERT with type conversion
            
            # ============= POSTGRESQL SPECIFIC =============
            re.compile(r"pg_(sleep|stat|table|database|user)", re.IGNORECASE),
            re.compile(r"pg_read_file[\s\+\/\*!]*\(", re.IGNORECASE),  # File read
            re.compile(r"copy[\s\+]*[\s\S]*?from[\s\+]*program", re.IGNORECASE),  # Command execution
            re.compile(r"::(int|text|char|varchar)", re.IGNORECASE),  # PostgreSQL type casting
            re.compile(r"chr[\s\+\/\*!]*\([0-9]+\)", re.IGNORECASE),  # CHR() function
            re.compile(r"current_setting[\s\+\/\*!]*\(", re.IGNORECASE),  # PostgreSQL settings
            
            # ============= ORACLE SPECIFIC =============
            re.compile(r"utl_http\.request", re.IGNORECASE),  # Oracle UTL_HTTP
            re.compile(r"dbms_(pipe|sql|xmlgen|crypto|random|lob)", re.IGNORECASE),  # Oracle DBMS packages
            re.compile(r"utl_(file|tcp|smtp|inaddr)", re.IGNORECASE),  # Oracle UTL packages
            re.compile(r"from[\s\+]*dual", re.IGNORECASE),  # Oracle DUAL table
            re.compile(r"rownum", re.IGNORECASE),  # Oracle ROWNUM
            
            # ============= MSSQL SPECIFIC =============
            re.compile(r"xp_(cmdshell|regread|regwrite|dirtree|enumgroups)", re.IGNORECASE),  # SQL Server extended procs
            re.compile(r"sp_(executesql|makewebtask|addextendedproc)", re.IGNORECASE),  # SQL Server stored procs
            re.compile(r"openrowset[\s\+\/\*!]*\(", re.IGNORECASE),  # OPENROWSET
            re.compile(r"opendatasource[\s\+\/\*!]*\(", re.IGNORECASE),  # OPENDATASOURCE
            re.compile(r"fn_(virtualfilestats|trace_gettable)", re.IGNORECASE),  # SQL Server functions
            
            # ============= ADVANCED BLIND TECHNIQUES =============
            re.compile(r"if[\s\+\/\*!]*\([\s\S]*?,[\s\S]*?,", re.IGNORECASE),  # IF(condition, true_val, false_val)
            re.compile(r"case[\s\+\/\*!]*when[\s\S]*?then[\s\S]*?else", re.IGNORECASE),  # CASE WHEN
            re.compile(r"iif[\s\+\/\*!]*\(", re.IGNORECASE),  # IIF() function
            re.compile(r"nullif[\s\+\/\*!]*\(", re.IGNORECASE),  # NULLIF()
            re.compile(r"ifnull[\s\+\/\*!]*\(", re.IGNORECASE),  # IFNULL()
            re.compile(r"coalesce[\s\+\/\*!]*\(", re.IGNORECASE),  # COALESCE()
            
            # ============= POLYGLOT INJECTIONS =============
            re.compile(r"sleep\([0-9]+\).*?benchmark", re.IGNORECASE),  # Multi-DB time functions
            re.compile(r"'\+[\s\+]*'", re.IGNORECASE),  # String concatenation '+'
            re.compile(r"'[\s\+]*\|\|[\s\+]*'", re.IGNORECASE),  # String concatenation '||'
            re.compile(r"0x[0-9a-f]+[\s\+]*union", re.IGNORECASE),  # Hex + UNION
            
            # ============= JSON/XML SQL INJECTION =============
            re.compile(r"\{[\s\S]*?(\$ne|\$gt|\$where|\$regex)[\s\S]*?\}", re.IGNORECASE),  # JSON injection
            re.compile(r"<(select|union|insert|delete)", re.IGNORECASE),  # XML injection
            re.compile(r"extractvalue[\s\+]*\(", re.IGNORECASE),
            re.compile(r"xmltype[\s\+]*\(", re.IGNORECASE),  # Oracle XMLType
            
            # ============= BYPASS QUOTES & STRING DELIMITERS =============
            re.compile(r"char[\s\+\/\*!]*\([0-9,\s]+\)", re.IGNORECASE),  # CHAR bypassing quotes
            re.compile(r"0x[0-9a-f]+[\s\+]*(=|<|>|like)", re.IGNORECASE),  # Hex comparison
            re.compile(r"binary[\s\+]*'", re.IGNORECASE),  # BINARY keyword
            re.compile(r"_binary[\s\+]*'", re.IGNORECASE),  # _binary modifier
            
            # ============= SECOND-ORDER & STORED INJECTION =============
            re.compile(r"call[\s\+\/\*!]*\w+[\s\+]*\(", re.IGNORECASE),  # CALL procedure
            re.compile(r"procedure[\s\+]*\w+", re.IGNORECASE),
            re.compile(r"trigger[\s\+]*(on|for|after|before)", re.IGNORECASE),
            
            # ============= OUT-OF-BAND & DNS EXFILTRATION =============
            re.compile(r"load_file[\s\+\/\*!]*\(['\"]\\\\\\\\", re.IGNORECASE),  # UNC path injection
            re.compile(r"select[\s\S]*?into[\s\+]*(outfile|dumpfile)", re.IGNORECASE),
            re.compile(r"bulk[\s\+]*insert", re.IGNORECASE),  # SQL Server BULK INSERT
            
            # ============= MYSQL SPECIFIC ADVANCED =============
            re.compile(r"information_schema\.(tables|columns|schemata)", re.IGNORECASE),
            re.compile(r"mysql\.(user|db|tables_priv|columns_priv)", re.IGNORECASE),
            re.compile(r"show[\s\+]*(databases|tables|columns|processlist)", re.IGNORECASE),
            re.compile(r"load[\s\+]*data[\s\+]*infile", re.IGNORECASE),
            
            # ============= EXTREMELY RARE BUT DANGEROUS =============
            re.compile(r"into[\s\+]*@", re.IGNORECASE),  # Variable injection
            re.compile(r"set[\s\+]*@[\w]+[\s\+]*=", re.IGNORECASE),  # SET @var
            re.compile(r"prepare[\s\+]*[\w]+[\s\+]*from", re.IGNORECASE),  # Prepared statements
            re.compile(r"execute[\s\+]*[\w]+[\s\+]*(using|into)", re.IGNORECASE),
            re.compile(r"\$or\s*:", re.IGNORECASE),  # MongoDB $or
            re.compile(r"\$and\s*:", re.IGNORECASE),  # MongoDB $and
            re.compile(r"\$where\s*:", re.IGNORECASE),  # MongoDB $where
            re.compile(r"\$regex\s*:", re.IGNORECASE),  # MongoDB $regex
        ]
        
        self.xss_patterns = [
            # ============= BASIC XSS PATTERNS =============
            re.compile(r"<script[\s\S]*?>[\s\S]*?</script>", re.IGNORECASE),
            re.compile(r"<script[^>]*>", re.IGNORECASE),
            re.compile(r"</script>", re.IGNORECASE),
            re.compile(r"<\s*script", re.IGNORECASE),  # With whitespace
            re.compile(r"<\s*/\s*script\s*>", re.IGNORECASE),
            
            # ============= JAVASCRIPT PROTOCOLS =============
            re.compile(r"javascript\s*:", re.IGNORECASE),
            re.compile(r"vbscript\s*:", re.IGNORECASE),
            re.compile(r"data\s*:[\s\S]*?text/html", re.IGNORECASE),
            re.compile(r"data\s*:[\s\S]*?base64", re.IGNORECASE),
            re.compile(r"data\s*:[\s\S]*?application/", re.IGNORECASE),
            re.compile(r"data\s*:[\s\S]*?image/svg", re.IGNORECASE),
            
            # ============= PROTOCOL OBFUSCATION =============
            re.compile(r"j[\s\x00]*a[\s\x00]*v[\s\x00]*a[\s\x00]*s[\s\x00]*c[\s\x00]*r[\s\x00]*i[\s\x00]*p[\s\x00]*t[\s\x00]*:", re.IGNORECASE),  # Null bytes
            re.compile(r"java\s*script\s*:", re.IGNORECASE),  # Space between java and script
            re.compile(r"jav&#[xX]?0*[aA][\s;]*script", re.IGNORECASE),  # HTML entity in javascript
            re.compile(r"&#[xX]?0*6[aA][\s;]*avascript", re.IGNORECASE),  # Hex 'j' in javascript
            re.compile(r"\\x6a\\x61\\x76\\x61\\x73\\x63\\x72\\x69\\x70\\x74", re.IGNORECASE),  # Hex encoded javascript
            re.compile(r"%6a%61%76%61%73%63%72%69%70%74", re.IGNORECASE),  # URL encoded javascript
            
            # ============= EVENT HANDLERS (COMPREHENSIVE) =============
            re.compile(r"on(load|click|error|focus|blur|change|submit|mouseover|mouseout|keydown|keyup|keypress)", re.IGNORECASE),
            re.compile(r"on(dblclick|mousedown|mouseup|mousemove|contextmenu|wheel)", re.IGNORECASE),
            re.compile(r"on(drag|dragstart|dragend|dragover|dragenter|dragleave|drop)", re.IGNORECASE),
            re.compile(r"on(scroll|resize|select|input|invalid|search)", re.IGNORECASE),
            re.compile(r"on(copy|cut|paste|abort|canplay|canplaythrough|durationchange)", re.IGNORECASE),
            re.compile(r"on(ended|loadeddata|loadedmetadata|loadstart|pause|play|playing)", re.IGNORECASE),
            re.compile(r"on(progress|ratechange|seeked|seeking|stalled|suspend|timeupdate)", re.IGNORECASE),
            re.compile(r"on(volumechange|waiting|animationstart|animationend|animationiteration)", re.IGNORECASE),
            re.compile(r"on(transitionend|message|open|show|toggle)", re.IGNORECASE),
            re.compile(r"on(beforeunload|unload|hashchange|pagehide|pageshow|popstate)", re.IGNORECASE),
            re.compile(r"on(storage|redo|undo|readystatechange|afterprint|beforeprint)", re.IGNORECASE),
            
            # ============= EVENT HANDLER OBFUSCATION =============
            re.compile(r"on[\s\x00]*error[\s\x00]*=", re.IGNORECASE),  # Null byte obfuscation
            re.compile(r"on[\s/]*error[\s/]*=", re.IGNORECASE),  # Slash obfuscation
            re.compile(r"on&#[xX]?[0-9a-fA-F]+;?error", re.IGNORECASE),  # HTML entity in event name
            re.compile(r"&#[xX]?0*6[fF][\s;]*n[a-z]+\s*=", re.IGNORECASE),  # Hex 'o' in on*
            re.compile(r"on\w+\s*=\s*['\"]?\s*alert", re.IGNORECASE),  # Generic onevt=alert
            re.compile(r"on\w+\s*=\s*['\"]?\s*prompt", re.IGNORECASE),  # Generic onevt=prompt
            re.compile(r"on\w+\s*=\s*['\"]?\s*confirm", re.IGNORECASE),  # Generic onevt=confirm
            
            # ============= DANGEROUS HTML TAGS =============
            re.compile(r"<iframe[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<object[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<embed[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<applet[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<meta[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<link[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<base[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<form[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<input[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<button[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<svg[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<math[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<marquee[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<audio[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<video[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<style[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<img[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<body[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<html[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<layer[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<bgsound[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<xml[\s\S]*?>", re.IGNORECASE),
            
            # ============= SVG/XML-BASED XSS =============
            re.compile(r"<svg[\s\S]*?on\w+", re.IGNORECASE),  # SVG with event handlers
            re.compile(r"<svg[\s\S]*?<script", re.IGNORECASE),  # SVG with script
            re.compile(r"<svg[\s\S]*?href[\s\S]*?javascript:", re.IGNORECASE),  # SVG href javascript
            re.compile(r"<animatetransform[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<set[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<animate[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<foreignobject[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<use[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<image[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<feimage[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<polygon[\s\S]*?>", re.IGNORECASE),
            
            # ============= CSS-BASED XSS =============
            re.compile(r"expression\s*\(", re.IGNORECASE),
            re.compile(r"behavior\s*:", re.IGNORECASE),
            re.compile(r"-moz-binding\s*:", re.IGNORECASE),
            re.compile(r"@import", re.IGNORECASE),
            re.compile(r"url\s*\(\s*['\"]?\s*javascript:", re.IGNORECASE),
            re.compile(r"url\s*\(\s*['\"]?\s*data:", re.IGNORECASE),
            re.compile(r"url\s*\(\s*['\"]?\s*vbscript:", re.IGNORECASE),
            re.compile(r"<style[\s\S]*?javascript:", re.IGNORECASE),
            re.compile(r"<link[\s\S]*?javascript:", re.IGNORECASE),
            
            # ============= HTML ENTITIES & ENCODING BYPASS =============
            re.compile(r"&#x[0-9a-f]+", re.IGNORECASE),  # Hex entities
            re.compile(r"&#\d+", re.IGNORECASE),  # Decimal entities
            re.compile(r"&[a-z]+;", re.IGNORECASE),  # Named entities
            re.compile(r"\\x[0-9a-f]{2}", re.IGNORECASE),  # Hex escape sequences
            re.compile(r"\\u[0-9a-f]{4}", re.IGNORECASE),  # Unicode escape sequences
            re.compile(r"%[0-9a-f]{2}%[0-9a-f]{2}", re.IGNORECASE),  # Double URL encoding
            re.compile(r"%[0-9a-f]{2}", re.IGNORECASE),  # URL encoding
            
            # ============= POLYGLOT & MULTI-CONTEXT XSS =============
            re.compile(r"jaVasCript:", re.IGNORECASE),  # Case variations
            re.compile(r"<[\s]*script", re.IGNORECASE),  # Leading spaces
            re.compile(r"</[\s]*script", re.IGNORECASE),
            re.compile(r"<img[\s\S]*?src[\s\S]*?=[\s\S]*?on", re.IGNORECASE),  # img src + event
            re.compile(r"<img[\s\S]*?on\w+[\s\S]*?src", re.IGNORECASE),  # img event + src
            re.compile(r"<a[\s\S]*?href[\s\S]*?javascript:", re.IGNORECASE),
            re.compile(r"<iframe[\s\S]*?src[\s\S]*?javascript:", re.IGNORECASE),
            
            # ============= DOM-BASED XSS SOURCES =============
            re.compile(r"document\s*\.\s*cookie", re.IGNORECASE),
            re.compile(r"document\s*\.\s*write", re.IGNORECASE),
            re.compile(r"document\s*\.\s*writeln", re.IGNORECASE),
            re.compile(r"document\s*\.\s*domain", re.IGNORECASE),
            re.compile(r"window\s*\.\s*location", re.IGNORECASE),
            re.compile(r"document\s*\.\s*location", re.IGNORECASE),
            re.compile(r"document\s*\.\s*URL", re.IGNORECASE),
            re.compile(r"document\s*\.\s*documentURI", re.IGNORECASE),
            re.compile(r"location\s*\.\s*hash", re.IGNORECASE),
            re.compile(r"location\s*\.\s*href", re.IGNORECASE),
            re.compile(r"location\s*\.\s*search", re.IGNORECASE),
            re.compile(r"location\s*\.\s*pathname", re.IGNORECASE),
            re.compile(r"eval\s*\(", re.IGNORECASE),
            re.compile(r"setTimeout\s*\(", re.IGNORECASE),
            re.compile(r"setInterval\s*\(", re.IGNORECASE),
            re.compile(r"Function\s*\(", re.IGNORECASE),
            re.compile(r"innerHTML\s*=", re.IGNORECASE),
            re.compile(r"outerHTML\s*=", re.IGNORECASE),
            re.compile(r"insertAdjacentHTML", re.IGNORECASE),
            
            # ============= JAVASCRIPT STRING BREAKING =============
            re.compile(r"['\"][\s]*\+[\s]*['\"]", re.IGNORECASE),  # String concatenation
            re.compile(r"['\"];[\s]*alert", re.IGNORECASE),  # Break out of string
            re.compile(r"['\"][\s]*\)[\s]*;[\s]*alert", re.IGNORECASE),
            re.compile(r"['\"][\s]*\}[\s]*;[\s]*alert", re.IGNORECASE),
            re.compile(r"['\"][\s]*;[\s]*prompt", re.IGNORECASE),
            re.compile(r"['\"][\s]*;[\s]*confirm", re.IGNORECASE),
            
            # ============= ADVANCED OBFUSCATION TECHNIQUES =============
            re.compile(r"<scr[\s\x00]*ipt", re.IGNORECASE),  # Broken script tag
            re.compile(r"<scr\\x69pt", re.IGNORECASE),  # Hex 'i' in script
            re.compile(r"<scr%69pt", re.IGNORECASE),  # URL encoded 'i'
            re.compile(r"<img[\s\S]*?src[\s\S]*?=[\s\S]*?x[\s\S]*?onerror", re.IGNORECASE),  # img src=x onerror
            re.compile(r"<body[\s\S]*?onload", re.IGNORECASE),
            re.compile(r"<input[\s\S]*?onfocus", re.IGNORECASE),
            re.compile(r"<select[\s\S]*?onfocus", re.IGNORECASE),
            re.compile(r"<textarea[\s\S]*?onfocus", re.IGNORECASE),
            re.compile(r"<keygen[\s\S]*?onfocus", re.IGNORECASE),
            re.compile(r"<video[\s\S]*?onerror", re.IGNORECASE),
            re.compile(r"<audio[\s\S]*?onerror", re.IGNORECASE),
            re.compile(r"<details[\s\S]*?open[\s\S]*?ontoggle", re.IGNORECASE),
            re.compile(r"<marquee[\s\S]*?onstart", re.IGNORECASE),
            
            # ============= TEMPLATE INJECTION VIA XSS =============
            re.compile(r"\{\{[\s\S]*?\}\}", re.IGNORECASE),  # Angular/Vue template syntax
            re.compile(r"\{%[\s\S]*?%\}", re.IGNORECASE),  # Jinja2/Django templates
            re.compile(r"\$\{[\s\S]*?\}", re.IGNORECASE),  # ES6 template literals
            re.compile(r"\[\[[\s\S]*?\]\]", re.IGNORECASE),  # Angular 1.x expressions
            
            # ============= UNCOMMON BUT DANGEROUS VECTORS =============
            re.compile(r"<isindex[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<form[\s\S]*?action[\s\S]*?javascript:", re.IGNORECASE),
            re.compile(r"<form[\s\S]*?action[\s\S]*?data:", re.IGNORECASE),
            re.compile(r"formaction[\s\S]*?=[\s\S]*?javascript:", re.IGNORECASE),
            re.compile(r"<frame[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<frameset[\s\S]*?>", re.IGNORECASE),
            re.compile(r"srcdoc[\s\S]*?=", re.IGNORECASE),  # iframe srcdoc
            re.compile(r"<plaintext>", re.IGNORECASE),
            re.compile(r"<xmp>", re.IGNORECASE),
            re.compile(r"<noscript[\s\S]*?<", re.IGNORECASE),
            
            # ============= MUTATION XSS (mXSS) =============
            re.compile(r"<noembed[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<noframes[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<title[\s\S]*?<", re.IGNORECASE),
            re.compile(r"<textarea[\s\S]*?<", re.IGNORECASE),
            re.compile(r"<style[\s\S]*?<", re.IGNORECASE),
            re.compile(r"<!--[\s\S]*?<script", re.IGNORECASE),
            re.compile(r"<!--[\s\S]*?javascript:", re.IGNORECASE),
            re.compile(r"<!--[\s\S]*?-->", re.IGNORECASE),  # Complete HTML comment
            
            # Attribute-based XSS
            re.compile(r"src\s*=[\s\S]*?javascript:", re.IGNORECASE),
            re.compile(r"href\s*=[\s\S]*?javascript:", re.IGNORECASE),
            re.compile(r"data\s*=[\s\S]*?javascript:", re.IGNORECASE),
            re.compile(r"action\s*=[\s\S]*?javascript:", re.IGNORECASE),
            re.compile(r"formaction\s*=[\s\S]*?javascript:", re.IGNORECASE),
            
            # Obfuscation techniques
            re.compile(r"\\x[0-9a-f]{2}", re.IGNORECASE),  # Hex escaping
            re.compile(r"\\u[0-9a-f]{4}", re.IGNORECASE),  # Unicode escaping
            re.compile(r"\\[0-7]{1,3}", re.IGNORECASE),  # Octal escaping
            
            # String concatenation
            re.compile(r"String\.fromCharCode", re.IGNORECASE),
            re.compile(r"eval\s*\(", re.IGNORECASE),
            re.compile(r"setTimeout\s*\(", re.IGNORECASE),
            re.compile(r"setInterval\s*\(", re.IGNORECASE),
            re.compile(r"Function\s*\(", re.IGNORECASE),
            
            # DOM-based XSS
            re.compile(r"document\.(write|writeln|cookie|location|domain)", re.IGNORECASE),
            re.compile(r"window\.(location|name|open)", re.IGNORECASE),
            re.compile(r"innerHTML|outerHTML", re.IGNORECASE),
            
            # Template injection patterns
            re.compile(r"\{\{[\s\S]*?\}\}", re.IGNORECASE),  # Angular/Vue
            re.compile(r"\${[\s\S]*?}", re.IGNORECASE),  # ES6 templates
            
            # Alert/Prompt/Confirm
            re.compile(r"(alert|prompt|confirm)\s*\(", re.IGNORECASE),
            
            # Advanced XSS evasion techniques
            re.compile(r"<\s*script", re.IGNORECASE),  # < script with space
            re.compile(r"script\s*>", re.IGNORECASE),  # script > with space
            re.compile(r"</\s*script\s*>", re.IGNORECASE),  # </ script >
            
            # HTML5 new tags and attributes
            re.compile(r"<\s*img[\s\S]*?src", re.IGNORECASE),  # IMG with src
            re.compile(r"<\s*body[\s\S]*?onload", re.IGNORECASE),  # BODY onload
            re.compile(r"<\s*img[\s\S]*?onerror", re.IGNORECASE),  # IMG onerror
            re.compile(r"<\s*input[\s\S]*?onfocus", re.IGNORECASE),  # INPUT onfocus
            
            # SVG-based XSS
            re.compile(r"<svg[\s\S]*?onload", re.IGNORECASE),  # SVG onload
            re.compile(r"<animatetransform", re.IGNORECASE),  # SVG animate
            re.compile(r"<set[\s\S]*?attributename", re.IGNORECASE),  # SVG set
            re.compile(r"<animate[\s\S]*?onbegin", re.IGNORECASE),  # SVG animate events
            
            # XML/XSLT injection
            re.compile(r"<\?xml", re.IGNORECASE),  # XML declaration
            re.compile(r"<\!DOCTYPE", re.IGNORECASE),  # DOCTYPE
            re.compile(r"<\!ENTITY", re.IGNORECASE),  # ENTITY declaration
            re.compile(r"<\!\[CDATA\[", re.IGNORECASE),  # CDATA section
            
            # JavaScript execution contexts
            re.compile(r"constructor", re.IGNORECASE),  # Constructor property
            re.compile(r"__proto__", re.IGNORECASE),  # Prototype pollution
            re.compile(r"prototype", re.IGNORECASE),  # Prototype chain
            
            # Event handler variations
            re.compile(r"onwheel\s*=", re.IGNORECASE),  # onwheel
            re.compile(r"onpointerover\s*=", re.IGNORECASE),  # onpointerover
            re.compile(r"onpointerenter\s*=", re.IGNORECASE),  # onpointerenter
            re.compile(r"onbeforescriptexecute\s*=", re.IGNORECASE),  # Firefox specific
            re.compile(r"onafterscriptexecute\s*=", re.IGNORECASE),  # Firefox specific
            
            # Filter bypass techniques
            re.compile(r"&#", re.IGNORECASE),  # HTML entities
            re.compile(r"%3C", re.IGNORECASE),  # < URL encoded
            re.compile(r"%3E", re.IGNORECASE),  # > URL encoded
            re.compile(r"\\x3c", re.IGNORECASE),  # < hex encoded
            re.compile(r"\\x3e", re.IGNORECASE),  # > hex encoded
            re.compile(r"\\u003c", re.IGNORECASE),  # < unicode
            re.compile(r"\\u003e", re.IGNORECASE),  # > unicode
            
            # Data exfiltration
            re.compile(r"fetch\s*\(", re.IGNORECASE),  # Fetch API
            re.compile(r"XMLHttpRequest", re.IGNORECASE),  # XHR
            re.compile(r"\.send\s*\(", re.IGNORECASE),  # XHR send
            re.compile(r"navigator\.", re.IGNORECASE),  # Navigator object
            re.compile(r"location\s*=", re.IGNORECASE),  # Location redirect
            re.compile(r"window\.location", re.IGNORECASE),  # Window location
            
            # WebSocket and event source
            re.compile(r"WebSocket\s*\(", re.IGNORECASE),  # WebSocket
            re.compile(r"EventSource\s*\(", re.IGNORECASE),  # Server-sent events
            
            # AngularJS specific
            re.compile(r"ng-", re.IGNORECASE),  # Angular directives
            re.compile(r"\{\{.*?\}\}", re.IGNORECASE),  # Angular expressions
            
            # React/JSX patterns
            re.compile(r"dangerouslySetInnerHTML", re.IGNORECASE),  # React XSS vector
            
            # MIME type confusion
            re.compile(r"text/html", re.IGNORECASE),  # HTML MIME type in data URLs
            re.compile(r"application/javascript", re.IGNORECASE),  # JS MIME type
        ]
        
        # HTML Injection patterns (harmless HTML tags without JavaScript)
        self.html_injection_patterns = [
            # Basic HTML tags without event handlers
            re.compile(r"<(u|b|i|strong|em|mark|small|del|ins|sub|sup|s|strike|big|tt)[\s>]", re.IGNORECASE),
            re.compile(r"<(h[1-6]|p|div|span|br|hr|pre|code|blockquote)[\s>]", re.IGNORECASE),
            re.compile(r"<(ul|ol|li|dl|dt|dd|table|tr|td|th|thead|tbody|tfoot)[\s>]", re.IGNORECASE),
            re.compile(r"<(a|abbr|address|area|article|aside|audio|video|canvas|caption)[\s>]", re.IGNORECASE),
            re.compile(r"<(center|cite|col|colgroup|data|datalist|details|dfn|dialog)[\s>]", re.IGNORECASE),
            re.compile(r"<(fieldset|figcaption|figure|footer|header|kbd|label|legend)[\s>]", re.IGNORECASE),
            re.compile(r"<(main|nav|output|picture|progress|q|rp|rt|ruby|s|samp)[\s>]", re.IGNORECASE),
            re.compile(r"<(section|source|summary|time|track|var|wbr)[\s>]", re.IGNORECASE),
            # Closing tags
            re.compile(r"</(u|b|i|strong|em|mark|small|del|ins|sub|sup|div|span|p|h[1-6])>", re.IGNORECASE),
        ]
        
        self.path_traversal_patterns = [
            # Basic directory traversal patterns - STRICT
            re.compile(r"\.\.[/\\]", re.IGNORECASE),  # ../ or ..\
            re.compile(r"\.\.$", re.IGNORECASE),  # .. at end
            re.compile(r"/\.\./", re.IGNORECASE),  # /../ anywhere
            re.compile(r"\\\.\.", re.IGNORECASE),  # \..
            re.compile(r"\.\./", re.IGNORECASE),  # ../
            re.compile(r"\.\.\\", re.IGNORECASE),  # ..\
            
            # URL encoded variants (single encoding)
            re.compile(r"%2e%2e[/\\]", re.IGNORECASE),  # %2e%2e/
            re.compile(r"%2e%2e%2f", re.IGNORECASE),  # %2e%2e%2f
            re.compile(r"%2e%2e%5c", re.IGNORECASE),  # %2e%2e%5c
            re.compile(r"\.\.%2f", re.IGNORECASE),  # ..%2f
            re.compile(r"\.\.%5c", re.IGNORECASE),  # ..%5c
            re.compile(r"%2e\.%2f", re.IGNORECASE),  # Mixed encoding
            re.compile(r"%2e\.%5c", re.IGNORECASE),  # Mixed encoding
            
            # Double URL encoded
            re.compile(r"%252e%252e[/\\]", re.IGNORECASE),
            re.compile(r"%252e%252e%252f", re.IGNORECASE),
            re.compile(r"%252e%252e%255c", re.IGNORECASE),
            re.compile(r"\.\.%252f", re.IGNORECASE),
            
            # Triple URL encoded
            re.compile(r"%25252e%25252e", re.IGNORECASE),
            
            # Unicode/UTF-8 encoding
            re.compile(r"%c0%ae%c0%ae[/\\]", re.IGNORECASE),
            re.compile(r"%c0%ae%c0%ae%c0%af", re.IGNORECASE),
            re.compile(r"%c0%ae%c0%ae%c1%9c", re.IGNORECASE),
            re.compile(r"%c0%2e%c0%2e[/\\]", re.IGNORECASE),
            re.compile(r"\.\xc0\xaf", re.IGNORECASE),
            re.compile(r"\xc0\xae\xc0\xae", re.IGNORECASE),
            
            # 16-bit Unicode encoding
            re.compile(r"%u002e%u002e[/\\]", re.IGNORECASE),
            re.compile(r"%%32%65%%32%65[/\\]", re.IGNORECASE),
            
            # Backslash and forward slash combinations
            re.compile(r"\.\.[/\\]+", re.IGNORECASE),
            re.compile(r"\.\.[\\/]+", re.IGNORECASE),
            re.compile(r"[/\\]+\.\.[/\\]+", re.IGNORECASE),
            
            # Null byte injection
            re.compile(r"\.\./+%00", re.IGNORECASE),
            re.compile(r"\.\.\\+%00", re.IGNORECASE),
            re.compile(r"%00", re.IGNORECASE),
            
            # Common sensitive file paths (Unix/Linux)
            re.compile(r"/etc/passwd", re.IGNORECASE),
            re.compile(r"/etc/shadow", re.IGNORECASE),
            re.compile(r"/etc/hosts", re.IGNORECASE),
            re.compile(r"/etc/hostname", re.IGNORECASE),
            re.compile(r"/etc/group", re.IGNORECASE),
            re.compile(r"/etc/issue", re.IGNORECASE),
            re.compile(r"/etc/motd", re.IGNORECASE),
            re.compile(r"/etc/mysql/my\.cnf", re.IGNORECASE),
            re.compile(r"/etc/ssh/sshd_config", re.IGNORECASE),
            re.compile(r"/proc/self/environ", re.IGNORECASE),
            re.compile(r"/proc/self/cmdline", re.IGNORECASE),
            re.compile(r"/proc/self/status", re.IGNORECASE),
            re.compile(r"/proc/self/fd/", re.IGNORECASE),
            re.compile(r"/proc/version", re.IGNORECASE),
            re.compile(r"/proc/cpuinfo", re.IGNORECASE),
            re.compile(r"/var/log/", re.IGNORECASE),
            re.compile(r"/var/mail/", re.IGNORECASE),
            re.compile(r"/var/www/", re.IGNORECASE),
            re.compile(r"/usr/local/", re.IGNORECASE),
            re.compile(r"/home/[^/]+/\.ssh", re.IGNORECASE),
            re.compile(r"\.bash_history", re.IGNORECASE),
            re.compile(r"\.ssh/id_rsa", re.IGNORECASE),
            re.compile(r"\.ssh/authorized_keys", re.IGNORECASE),
            
            # Common sensitive file paths (Windows)
            re.compile(r"c:[/\\]+windows[/\\]+system32", re.IGNORECASE),
            re.compile(r"c:[/\\]+windows[/\\]+win\.ini", re.IGNORECASE),
            re.compile(r"c:[/\\]+windows[/\\]+system\.ini", re.IGNORECASE),
            re.compile(r"[/\\]+windows[/\\]+system32", re.IGNORECASE),
            re.compile(r"boot\.ini", re.IGNORECASE),
            re.compile(r"win\.ini", re.IGNORECASE),
            re.compile(r"system\.ini", re.IGNORECASE),
            re.compile(r"[/\\]+windows[/\\]+repair[/\\]+sam", re.IGNORECASE),
            re.compile(r"[/\\]+windows[/\\]+repair[/\\]+system", re.IGNORECASE),
            re.compile(r"[/\\]+windows[/\\]+repair[/\\]+software", re.IGNORECASE),
            re.compile(r"[/\\]+windows[/\\]+repair[/\\]+security", re.IGNORECASE),
            re.compile(r"[/\\]+winnt[/\\]+system32", re.IGNORECASE),
            re.compile(r"[/\\]+inetpub[/\\]+wwwroot", re.IGNORECASE),
            re.compile(r"[/\\]+boot\.ini", re.IGNORECASE),
            re.compile(r"[/\\]+autoexec\.bat", re.IGNORECASE),
            re.compile(r"[/\\]+config\.sys", re.IGNORECASE),
            
            # Absolute path attempts
            re.compile(r"^[/\\]+etc[/\\]", re.IGNORECASE),
            re.compile(r"^[/\\]+proc[/\\]", re.IGNORECASE),
            re.compile(r"^[/\\]+var[/\\]", re.IGNORECASE),
            re.compile(r"^[/\\]+usr[/\\]", re.IGNORECASE),
            re.compile(r"^[/\\]+home[/\\]", re.IGNORECASE),
            re.compile(r"^[/\\]+root[/\\]", re.IGNORECASE),
            re.compile(r"^c:[/\\]", re.IGNORECASE),
            re.compile(r"^[a-z]:[/\\]", re.IGNORECASE),
            
            # Web application specific paths
            re.compile(r"web\.config", re.IGNORECASE),
            re.compile(r"\.htaccess", re.IGNORECASE),
            re.compile(r"\.htpasswd", re.IGNORECASE),
            re.compile(r"\.env", re.IGNORECASE),
            re.compile(r"\.git[/\\]", re.IGNORECASE),
            re.compile(r"\.svn[/\\]", re.IGNORECASE),
            re.compile(r"\.DS_Store", re.IGNORECASE),
            re.compile(r"\.bash_profile", re.IGNORECASE),
            re.compile(r"\.bashrc", re.IGNORECASE),
            re.compile(r"\.profile", re.IGNORECASE),
            
            # Application config files
            re.compile(r"config\.(php|inc|conf|cfg|xml|json|yml|yaml)", re.IGNORECASE),
            re.compile(r"database\.(php|inc|conf|cfg|xml|json|yml|yaml)", re.IGNORECASE),
            re.compile(r"settings\.(php|inc|conf|cfg|xml|json|yml|yaml)", re.IGNORECASE),
            re.compile(r"app\.(php|inc|conf|cfg|xml|json|yml|yaml)", re.IGNORECASE),
        ]
        
        self.bot_patterns = [
            re.compile(r"bot|crawler|spider|scraper", re.IGNORECASE),
            re.compile(r"curl|wget|python|java", re.IGNORECASE),
            re.compile(r"automated|scanner|vulnerability", re.IGNORECASE),
        ]
        
        # Command Injection patterns - Must be specific to avoid false positives
        # Do NOT block common punctuation like ; & | alone - they're used in normal text
        self.command_injection_patterns = [
            # Command substitution (high confidence attacks)
            re.compile(r"`[^`]+`", re.IGNORECASE),  # Backtick command substitution
            re.compile(r"\$\([^)]+\)", re.IGNORECASE),  # $() command substitution
            re.compile(r"\$\{[^}]+\}", re.IGNORECASE),  # ${} variable expansion with content
            
            # Unix/Linux commands with arguments (more specific patterns)
            re.compile(r"\bcat\s+/etc/", re.IGNORECASE),  # cat /etc/passwd etc.
            re.compile(r"\bls\s+-[la]", re.IGNORECASE),  # ls with flags
            re.compile(r"\bwhoami\b", re.IGNORECASE),  # whoami command
            re.compile(r"\buname\s+-[a]", re.IGNORECASE),  # uname -a
            re.compile(r"\bchmod\s+[0-7]{3,4}\b", re.IGNORECASE),  # chmod with octal
            re.compile(r"\bchown\s+\w+:\w+", re.IGNORECASE),  # chown user:group
            re.compile(r"\bwget\s+https?://", re.IGNORECASE),  # wget with URL
            re.compile(r"\bcurl\s+https?://", re.IGNORECASE),  # curl with URL
            re.compile(r"\bnc\s+-[lvp]", re.IGNORECASE),  # netcat with flags
            re.compile(r"\bbash\s+-[ci]", re.IGNORECASE),  # bash with flags
            re.compile(r"\bsh\s+-[ci]", re.IGNORECASE),  # sh with flags
            re.compile(r"/bin/(?:bash|sh|cat|ls|nc)", re.IGNORECASE),  # Binary paths
            re.compile(r"\bcmd\.exe\s*/c", re.IGNORECASE),  # Windows cmd /c
            re.compile(r"\bpowershell\s+-[ecw]", re.IGNORECASE),  # PowerShell with flags
            
            # Function calls for code execution
            re.compile(r"\bsystem\s*\([\"'][^)]+[\"']\)", re.IGNORECASE),  # system("cmd")
            re.compile(r"\bexec\s*\([\"'][^)]+[\"']\)", re.IGNORECASE),  # exec("cmd")
            re.compile(r"\bpassthru\s*\([\"'][^)]+[\"']\)", re.IGNORECASE),  # PHP passthru
            re.compile(r"\bshell_exec\s*\([\"'][^)]+[\"']\)", re.IGNORECASE),  # PHP shell_exec
            re.compile(r"\bproc_open\s*\(", re.IGNORECASE),  # PHP proc_open
            re.compile(r"\bpopen\s*\([\"'][^)]+[\"']\)", re.IGNORECASE),  # popen("cmd")
            
            # Chained commands (require command on both sides)
            re.compile(r"\b\w+\s*&&\s*\w+", re.IGNORECASE),  # cmd1 && cmd2
            re.compile(r"\b\w+\s*\|\|\s*\w+", re.IGNORECASE),  # cmd1 || cmd2
            re.compile(r"\b\w+\s*;\s*(?:cat|ls|id|whoami|wget|curl)\b", re.IGNORECASE),  # cmd; dangerous_cmd
            
            # Dangerous redirections (with paths)
            re.compile(r">\s*/(?:etc|tmp|var)", re.IGNORECASE),  # Write to system dirs
            re.compile(r"<\s*/(?:etc|proc)", re.IGNORECASE),  # Read from system dirs
        ]
        
        # LDAP Injection patterns
        self.ldap_injection_patterns = [
            re.compile(r"\*\)", re.IGNORECASE),  # LDAP wildcard
            re.compile(r"\(\|", re.IGNORECASE),  # LDAP OR
            re.compile(r"\(&", re.IGNORECASE),  # LDAP AND
            re.compile(r"\(!", re.IGNORECASE),  # LDAP NOT
            re.compile(r"admin\)", re.IGNORECASE),  # Common LDAP injection
            re.compile(r"\)\(", re.IGNORECASE),  # Filter bypass
            re.compile(r"objectClass=\*", re.IGNORECASE),  # LDAP enumeration
        ]
        
        # XML/XXE Injection patterns
        self.xml_injection_patterns = [
            re.compile(r"<!ENTITY", re.IGNORECASE),  # Entity declaration
            re.compile(r"<!DOCTYPE", re.IGNORECASE),  # DOCTYPE declaration
            re.compile(r"SYSTEM\s+['\"]", re.IGNORECASE),  # External entity
            re.compile(r"PUBLIC\s+['\"]", re.IGNORECASE),  # Public entity
            re.compile(r"file://", re.IGNORECASE),  # File protocol
            re.compile(r"php://", re.IGNORECASE),  # PHP wrapper
            re.compile(r"expect://", re.IGNORECASE),  # Expect wrapper
            re.compile(r"data://", re.IGNORECASE),  # Data protocol
            re.compile(r"gopher://", re.IGNORECASE),  # Gopher protocol
        ]
        
        # SSRF (Server-Side Request Forgery) patterns
        self.ssrf_patterns = [
            re.compile(r"localhost", re.IGNORECASE),  # Localhost
            re.compile(r"127\.0\.0\.1", re.IGNORECASE),  # Loopback IP
            re.compile(r"0\.0\.0\.0", re.IGNORECASE),  # All interfaces
            re.compile(r"169\.254\.", re.IGNORECASE),  # Link-local
            re.compile(r"192\.168\.", re.IGNORECASE),  # Private network
            re.compile(r"10\.\d+\.\d+\.\d+", re.IGNORECASE),  # Private network
            re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\.", re.IGNORECASE),  # Private network
            re.compile(r"file://", re.IGNORECASE),  # File protocol
            re.compile(r"dict://", re.IGNORECASE),  # Dict protocol
            re.compile(r"ftp://", re.IGNORECASE),  # FTP protocol
            re.compile(r"gopher://", re.IGNORECASE),  # Gopher protocol
            re.compile(r"ldap://", re.IGNORECASE),  # LDAP protocol
            re.compile(r"tftp://", re.IGNORECASE),  # TFTP protocol
        ]
        
        # Template Injection patterns
        self.template_injection_patterns = [
            re.compile(r"\{\{.*?\}\}", re.IGNORECASE),  # Jinja2/Angular
            re.compile(r"\{%.*?%\}", re.IGNORECASE),  # Jinja2 statements
            re.compile(r"\$\{.*?\}", re.IGNORECASE),  # EL/OGNL
            re.compile(r"<%.*?%>", re.IGNORECASE),  # JSP/ASP
            re.compile(r"@\{.*?\}", re.IGNORECASE),  # Thymeleaf
            re.compile(r"#\{.*?\}", re.IGNORECASE),  # SpEL
        ]
        
        # RCE (Remote Code Execution) patterns
        self.rce_patterns = [
            re.compile(r"__import__", re.IGNORECASE),  # Python import
            re.compile(r"eval\s*\(", re.IGNORECASE),  # Eval function
            re.compile(r"exec\s*\(", re.IGNORECASE),  # Exec function
            re.compile(r"compile\s*\(", re.IGNORECASE),  # Compile function
            re.compile(r"os\.system", re.IGNORECASE),  # OS system
            re.compile(r"subprocess", re.IGNORECASE),  # Subprocess
            re.compile(r"Runtime\.getRuntime", re.IGNORECASE),  # Java Runtime
            re.compile(r"ProcessBuilder", re.IGNORECASE),  # Java ProcessBuilder
            re.compile(r"deserialize", re.IGNORECASE),  # Deserialization
            re.compile(r"unserialize", re.IGNORECASE),  # PHP unserialize
            re.compile(r"pickle\.loads", re.IGNORECASE),  # Python pickle
        ]
    
    def _get_enabled_features(self) -> List[str]:
        """Get list of enabled security features"""
        features = []
        if self.settings.sql_injection_protection:
            features.append("SQL Injection Protection")
        if self.settings.xss_protection:
            features.append("XSS Protection")
        if self.settings.ddos_protection:
            features.append("DDoS Protection")
        if self.settings.ip_blocking_enabled:
            features.append("IP Blocking")
        if self.settings.bot_detection_enabled:
            features.append("Bot Detection")
        if self.settings.rate_limit_enabled:
            features.append("Rate Limiting")
        features.append("Path Traversal Protection")  # Always enabled
        return features
    
    def _log_to_windows_defender(self, security_event: SecurityEvent):
        """Log a security event to Windows Defender/Event Log"""
        if self.defender_integration and security_event.blocked:
            try:
                self.defender_integration.log_security_event(
                    event_id=security_event.id,
                    threat_type=security_event.threat_type,
                    threat_level=security_event.threat_level.value if hasattr(security_event.threat_level, 'value') else str(security_event.threat_level),
                    source_ip=security_event.source_ip,
                    target_url=security_event.target_url,
                    blocked=security_event.blocked,
                    details=security_event.details
                )
            except Exception as e:
                logger.debug(f"Windows Defender logging failed: {e}")
    
    async def process_request(self, 
                            method: str,
                            url: str, 
                            headers: Dict[str, str],
                            body: Optional[str] = None,
                            client_ip: str = "unknown") -> Tuple[bool, SecurityEvent]:
        """
        Process incoming HTTP request through WAF security checks
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            headers: HTTP headers dictionary
            body: Request body content
            client_ip: Client IP address
            
        Returns:
            Tuple of (allow_request: bool, security_event: SecurityEvent)
        """
        start_time = time.time()
        self.metrics.total_requests += 1
        print(f"🔍 WAF Engine: process_request called! Total requests now: {self.metrics.total_requests}")
        
        # Whitelist API endpoints from WAF checks to prevent self-blocking
        whitelisted_paths = [
            '/api/v1/rules/toggle',
            '/api/v1/rules/status',
            '/api/v1/statistics',
            '/api/v1/connections/active',
            '/api/v1/connections/logs',
            '/api/v1/ips/activity',
            '/api/v1/system/uptime',
            '/api/v1/blocked-ips',
            '/api/v1/event-logs',
            '/api/v1/network/',
            '/api/v1/speed/',
            '/api/v1/activity/',
            '/api/v1/chat',  # AI chatbot endpoint
            '/api/v1/chat-test',  # AI chatbot test endpoint  
            '/api/v1/chat-test-post',  # POST test
            '/api/v1/ai-stats',  # AI statistics
            '/api/v1/ai-events',  # AI events
            '/api/v1/victims',  # Victim tracking endpoint
            '/api/log-victim',  # Victim logging endpoint (vulnerable app)
            '/api/v1/activity/log',  # Internal activity logging from vulnerable app
            # '/admin/login' - REMOVED from whitelist to demonstrate WAF blocking XSS/SQL injection in login form
            '/admin/logout',     # Whitelist admin logout endpoint
            '/health',
            '/static/',
            '/favicon.ico'
        ]
        
        # Extract path from URL for whitelisting check
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        url_path = parsed_url.path
        
        # Check if URL path matches any whitelisted path
        for whitelisted_path in whitelisted_paths:
            if url_path.startswith(whitelisted_path) or whitelisted_path in url_path:
                # Create a simple allow event
                event_id = f"WAF_{int(time.time())}_{len(self.security_events)}"
                security_event = SecurityEvent(
                    id=event_id,
                    timestamp=datetime.now(),
                    threat_type="none",
                    threat_level=ThreatLevel.LOW,
                    source_ip=client_ip,
                    target_url=url,
                    user_agent=headers.get("User-Agent", "unknown"),
                    action_taken=ActionType.ALLOW,
                    details={"whitelisted": True, "reason": "API endpoint"}
                )
                return True, security_event
        
        # Generate unique event ID
        event_id = f"WAF_{int(time.time())}_{len(self.security_events)}"
        
        # Basic request info
        user_agent = headers.get("User-Agent", "unknown")
        
        # DDoS detection - check for suspicious patterns (only if enabled)
        ddos_indicators = {"score": 0, "indicators": []}
        if self.settings.ddos_protection:
            ddos_indicators = await self._detect_ddos_patterns(method, url, headers, user_agent, client_ip)
            # Log DDoS score for debugging
            if ddos_indicators["score"] > 0:
                print(f"🛡️ DDoS Score: {ddos_indicators['score']} for IP {client_ip} (threshold: 5)")
                print(f"   Indicators: {', '.join(ddos_indicators['indicators'])}")
        
        # Initialize security event
        security_event = SecurityEvent(
            id=event_id,
            timestamp=datetime.now(),
            threat_type="none",
            threat_level=ThreatLevel.LOW,
            source_ip=client_ip,
            target_url=url,
            user_agent=user_agent,
            action_taken=ActionType.ALLOW,
            details={"method": method, "headers": dict(headers), "ddos_score": ddos_indicators["score"]}
        )

        # Observe-only AI scoring: attach score to event details (do not change action)
        if getattr(self, "ai_scorer", None) is not None:
            try:
                ai_result = self.ai_scorer.score_event(security_event)
                security_event.details["ai"] = ai_result
                # attach model-backed score if available (observe-only)
                if getattr(self, "model_scorer", None) is not None:
                    try:
                        model_res = self.model_scorer.score_event_with_model(security_event)
                        if model_res:
                            security_event.details["ai"]["model"] = model_res
                            # check flagging thresholds (observe-only)
                            try:
                                if self.settings.ai_enabled and self.settings.ai_flagging_enabled:
                                    flagged = False
                                    reasons = []
                                    # heuristic
                                    hscore = float(security_event.details["ai"].get("ai_score", 0))
                                    if hscore >= float(self.settings.ai_heuristic_threshold):
                                        flagged = True
                                        reasons.append(f"heuristic:{hscore}")

                                    # DISABLED: Model-based flagging (too many false positives)
                                    # Only use heuristic scoring which is more reliable
                                    # if isinstance(model_res, dict):
                                    #     mc = model_res.get("model_confidence")
                                    #     if mc is not None and float(mc) >= float(self.settings.ai_model_confidence_threshold):
                                    #         flagged = True
                                    #         reasons.append(f"model_conf:{mc}")

                                    #     # anomaly score
                                    #     ms = model_res.get("model_score")
                                    #     if ms is not None and float(ms) >= float(self.settings.ai_model_anomaly_threshold):
                                    #         flagged = True
                                    #         reasons.append(f"model_anom:{ms}")

                                    if flagged:
                                        security_event.details["ai"]["flagged"] = True
                                        security_event.details["ai"]["flag_reasons"] = reasons
                                        # AI is for alerts only - never blocks IPs directly
                            except Exception:
                                pass
                    except Exception:
                        pass
            except Exception as e:
                logger.error("AI scoring failed", error=str(e))
        
        # Block if DDoS score is high (threshold: 5 to reduce false positives)
        if self.settings.ddos_protection and ddos_indicators["score"] >= 5:
            security_event.threat_type = "ddos_attack"
            security_event.threat_level = ThreatLevel.CRITICAL
            security_event.action_taken = ActionType.BLOCK
            security_event.blocked = True
            security_event.details["ddos_indicators"] = ddos_indicators["indicators"]
            
            logger.critical("DDoS attack detected", 
                          client_ip=client_ip, 
                          score=ddos_indicators["score"],
                          indicators=ddos_indicators["indicators"])
            
            self.metrics.blocked_requests += 1
            self.metrics.threats_detected += 1
            self.security_events.append(security_event)
            self._log_event_to_db(security_event)
            self._log_to_windows_defender(security_event)  # Log DDoS to Windows Defender
            await self._auto_block_ip(client_ip, "DDoS attack pattern detected")
            return False, security_event
        
        try:
            # Check if IP is blocked (only if auto IP blocking is enabled)
            if await self._is_ip_blocked(client_ip):
                if self.settings.auto_ip_blocking:
                    security_event.threat_type = "blocked_ip"
                    security_event.threat_level = ThreatLevel.HIGH
                    security_event.action_taken = ActionType.BLOCK
                    security_event.blocked = True
                    security_event.details["reason"] = "IP in blocklist"
                    
                    logger.warning("Blocked request from banned IP", 
                                 client_ip=client_ip, url=url)
                    
                    self.metrics.blocked_requests += 1
                    self.security_events.append(security_event)
                    self._log_event_to_db(security_event)
                    return False, security_event
                else:
                    # IP is in blocklist but auto_ip_blocking is disabled - allow request
                    print(f"🔓 IP {client_ip} is in blocklist but Auto IP Blocking is OFF - allowing request")
                    logger.info("IP in blocklist but auto blocking disabled - allowing", client_ip=client_ip)
            
            # Rate limiting check
            print(f"🔍 Rate Limit Check: enabled={self.settings.rate_limit_enabled}, IP={client_ip}")
            if self.settings.rate_limit_enabled:
                if not await self._check_rate_limit(client_ip):
                    security_event.threat_type = "rate_limit_exceeded"
                    security_event.threat_level = ThreatLevel.MEDIUM
                    security_event.action_taken = ActionType.RATE_LIMIT
                    security_event.blocked = True
                    security_event.details["rate_limit"] = {
                        "requests": self.settings.rate_limit_requests,
                        "window": self.settings.rate_limit_window
                    }
                    
                    logger.warning("Rate limit exceeded", 
                                 client_ip=client_ip, url=url)
                    
                    self.metrics.blocked_requests += 1
                    self.security_events.append(security_event)
                    self._log_event_to_db(security_event)
                    return False, security_event
            else:
                print(f"✓ Rate limiting is DISABLED - allowing request from {client_ip}")
            
            # Quick pre-check: If request contains HTML tags, skip SQL detection (it's likely XSS)
            import urllib.parse
            combined_input = f"{url} {body or ''}"
            decoded_input = urllib.parse.unquote(combined_input)
            has_html_tags = re.search(r'</?[a-z]+[\s/>]', combined_input, re.IGNORECASE) or \
                           re.search(r'</?[a-z]+[\s/>]', decoded_input, re.IGNORECASE)
            
            # SQL Injection detection - CHECK FIRST (most critical) but skip if HTML tags present
            if self.settings.sql_injection_protection and not has_html_tags:
                sql_detected = await self._detect_sql_injection(url, body)
                if sql_detected:
                    security_event.threat_type = "sql_injection"
                    security_event.threat_level = ThreatLevel.CRITICAL
                    security_event.action_taken = ActionType.BLOCK
                    security_event.blocked = True
                    security_event.details["detected_patterns"] = sql_detected
                    
                    logger.critical("SQL injection attempt detected", 
                                  client_ip=client_ip, url=url, 
                                  patterns=sql_detected)
                    
                    self.metrics.blocked_requests += 1
                    self.metrics.threats_detected += 1
                    self.security_events.append(security_event)
                    self._log_event_to_db(security_event)
                    self._log_to_windows_defender(security_event)  # Log to Windows Defender
                    
                    # Auto-block IP for SQL injection attempts
                    await self._auto_block_ip(client_ip, "SQL injection attempt")
                    
                    return False, security_event
            
            # XSS detection - CHECK AFTER SQL injection to avoid misclassification
            if self.settings.xss_protection:
                xss_detected = await self._detect_xss(url, body)
                if xss_detected:
                    security_event.threat_type = "xss_attempt"
                    security_event.threat_level = ThreatLevel.HIGH
                    security_event.action_taken = ActionType.BLOCK
                    security_event.blocked = True
                    security_event.details["detected_patterns"] = xss_detected
                    
                    logger.error("XSS attempt detected", 
                               client_ip=client_ip, url=url,
                               patterns=xss_detected)
                    
                    self.metrics.blocked_requests += 1
                    self.metrics.threats_detected += 1
                    self.security_events.append(security_event)
                    self._log_event_to_db(security_event)
                    self._log_to_windows_defender(security_event)  # Log to Windows Defender
                    return False, security_event
            else:
                # XSS protection is disabled - log and allow
                print(f"✓ XSS Protection DISABLED - allowing request from {client_ip}")
            
            # HTML Injection detection - CHECK AFTER XSS (for harmless HTML tags)
            html_injection_detected = await self._detect_html_injection(url, body)
            if html_injection_detected:
                security_event.threat_type = "html_injection"
                security_event.threat_level = ThreatLevel.MEDIUM
                security_event.action_taken = ActionType.BLOCK
                security_event.blocked = True
                security_event.details["detected_patterns"] = html_injection_detected
                
                logger.warning("HTML injection detected", 
                           client_ip=client_ip, url=url,
                           patterns=html_injection_detected)
                
                self.metrics.blocked_requests += 1
                self.metrics.threats_detected += 1
                self.security_events.append(security_event)
                self._log_event_to_db(security_event)
                self._log_to_windows_defender(security_event)  # Log to Windows Defender
                return False, security_event
            
            # Path Traversal detection
            if self.settings.path_traversal_protection:
                path_traversal_detected = await self._detect_path_traversal(url, body)
                if path_traversal_detected:
                    security_event.threat_type = "path_traversal"
                    security_event.threat_level = ThreatLevel.CRITICAL
                    security_event.action_taken = ActionType.BLOCK
                    security_event.blocked = True
                    security_event.details["detected_patterns"] = path_traversal_detected
                    
                    logger.critical("Path traversal attempt detected", 
                                  client_ip=client_ip, url=url,
                                  patterns=path_traversal_detected)
                    
                    self.metrics.blocked_requests += 1
                    self.metrics.threats_detected += 1
                    self.security_events.append(security_event)
                    self._log_event_to_db(security_event)
                    self._log_to_windows_defender(security_event)  # Log to Windows Defender
                    
                    # Auto-block IP for path traversal attempts
                    await self._auto_block_ip(client_ip, "Path traversal attempt")
                    
                    return False, security_event
            
            # Authentication Bypass detection
            auth_bypass_detected = await self._detect_auth_bypass(url, body)
            if auth_bypass_detected:
                security_event.threat_type = "auth_bypass_attempt"
                security_event.threat_level = ThreatLevel.CRITICAL
                security_event.action_taken = ActionType.BLOCK
                security_event.blocked = True
                security_event.details["detected_patterns"] = auth_bypass_detected
                
                logger.critical("Authentication bypass attempt detected", 
                              client_ip=client_ip, url=url,
                              patterns=auth_bypass_detected)
                
                self.metrics.blocked_requests += 1
                self.metrics.threats_detected += 1
                self.security_events.append(security_event)
                self._log_event_to_db(security_event)
                self._log_to_windows_defender(security_event)  # Log to Windows Defender
                
                # Auto-block IP for auth bypass attempts
                await self._auto_block_ip(client_ip, "Authentication bypass attempt")
                
                return False, security_event
            
            # Command Injection detection
            command_injection_detected = await self._detect_command_injection(url, body)
            if command_injection_detected:
                security_event.threat_type = "command_injection"
                security_event.threat_level = ThreatLevel.CRITICAL
                security_event.action_taken = ActionType.BLOCK
                security_event.blocked = True
                security_event.details["detected_patterns"] = command_injection_detected
                
                logger.critical("Command injection attempt detected", 
                              client_ip=client_ip, url=url)
                
                self.metrics.blocked_requests += 1
                self.metrics.threats_detected += 1
                self._log_to_windows_defender(security_event)  # Log to Windows Defender
                self.security_events.append(security_event)
                self._log_event_to_db(security_event)
                await self._auto_block_ip(client_ip, "Command injection attempt")
                return False, security_event
            
            # LDAP Injection detection
            ldap_injection_detected = await self._detect_ldap_injection(url, body)
            if ldap_injection_detected:
                security_event.threat_type = "ldap_injection"
                security_event.threat_level = ThreatLevel.HIGH
                security_event.action_taken = ActionType.BLOCK
                security_event.blocked = True
                security_event.details["detected_patterns"] = ldap_injection_detected
                
                logger.error("LDAP injection attempt detected", 
                           client_ip=client_ip, url=url)
                
                self.metrics.blocked_requests += 1
                self.metrics.threats_detected += 1
                self.security_events.append(security_event)
                self._log_event_to_db(security_event)
                return False, security_event
            
            # XML/XXE Injection detection
            xml_injection_detected = await self._detect_xml_injection(url, body)
            if xml_injection_detected:
                security_event.threat_type = "xml_injection"
                security_event.threat_level = ThreatLevel.CRITICAL
                security_event.action_taken = ActionType.BLOCK
                security_event.blocked = True
                security_event.details["detected_patterns"] = xml_injection_detected
                
                logger.critical("XML/XXE injection attempt detected", 
                              client_ip=client_ip, url=url)
                
                self.metrics.blocked_requests += 1
                self.metrics.threats_detected += 1
                self.security_events.append(security_event)
                self._log_event_to_db(security_event)
                await self._auto_block_ip(client_ip, "XML injection attempt")
                return False, security_event
            
            # SSRF detection (exempt internal API calls from localhost)
            is_localhost = client_ip in ['127.0.0.1', 'localhost', '::1']
            is_api_route = url_path.startswith('/api/v1/')
            
            if not (is_localhost and is_api_route):
                ssrf_detected = await self._detect_ssrf(url, body)
                if ssrf_detected:
                    security_event.threat_type = "ssrf_attempt"
                    security_event.threat_level = ThreatLevel.HIGH
                    security_event.action_taken = ActionType.BLOCK
                    security_event.blocked = True
                    security_event.details["detected_patterns"] = ssrf_detected
                    
                    logger.error("SSRF attempt detected", 
                               client_ip=client_ip, url=url)
                    
                    self.metrics.blocked_requests += 1
                    self.metrics.threats_detected += 1
                    self.security_events.append(security_event)
                    self._log_event_to_db(security_event)
                    return False, security_event
            
            # Template Injection detection
            template_injection_detected = await self._detect_template_injection(url, body)
            if template_injection_detected:
                security_event.threat_type = "template_injection"
                security_event.threat_level = ThreatLevel.CRITICAL
                security_event.action_taken = ActionType.BLOCK
                security_event.blocked = True
                security_event.details["detected_patterns"] = template_injection_detected
                
                logger.critical("Template injection attempt detected", 
                              client_ip=client_ip, url=url)
                
                self.metrics.blocked_requests += 1
                self.metrics.threats_detected += 1
                self.security_events.append(security_event)
                self._log_event_to_db(security_event)
                await self._auto_block_ip(client_ip, "Template injection attempt")
                return False, security_event
            
            # RCE detection
            rce_detected = await self._detect_rce(url, body)
            if rce_detected:
                security_event.threat_type = "rce_attempt"
                security_event.threat_level = ThreatLevel.CRITICAL
                security_event.action_taken = ActionType.BLOCK
                security_event.blocked = True
                security_event.details["detected_patterns"] = rce_detected
                
                logger.critical("Remote Code Execution attempt detected", 
                              client_ip=client_ip, url=url)
                
                self.metrics.blocked_requests += 1
                self.metrics.threats_detected += 1
                self.security_events.append(security_event)
                self._log_event_to_db(security_event)
                await self._auto_block_ip(client_ip, "RCE attempt")
                return False, security_event
            
            # Bot detection
            if self.settings.bot_detection_enabled:
                bot_detected = await self._detect_bot(user_agent)
                if bot_detected:
                    security_event.threat_type = "bot_detected"
                    security_event.threat_level = ThreatLevel.MEDIUM
                    security_event.action_taken = ActionType.LOG
                    security_event.details["bot_type"] = bot_detected
                    
                    logger.info("Bot detected", 
                              client_ip=client_ip, user_agent=user_agent,
                              bot_type=bot_detected)
            
            # Request allowed
            self.metrics.allowed_requests += 1
            self.security_events.append(security_event)
            self._log_event_to_db(security_event)
            
            # Update response time metrics
            processing_time = time.time() - start_time
            self.metrics.avg_response_time = (
                (self.metrics.avg_response_time * (self.metrics.total_requests - 1) + processing_time)
                / self.metrics.total_requests
            )
            
            logger.info("Request processed successfully", 
                       client_ip=client_ip, url=url, 
                       processing_time=processing_time)
            
            return True, security_event
            
        except Exception as e:
            logger.error("Error processing request", 
                        client_ip=client_ip, url=url, error=str(e))
            
            security_event.threat_type = "processing_error"
            security_event.threat_level = ThreatLevel.LOW
            security_event.action_taken = ActionType.ALLOW
            security_event.details["error"] = str(e)
            
            self.security_events.append(security_event)
            return True, security_event
    
    async def _is_ip_blocked(self, ip: str) -> bool:
        """Check if IP address is in blocklist"""
        if ip in self.blocked_ips:
            block_data = self.blocked_ips[ip]
            # Handle both old datetime format and new dict format
            if isinstance(block_data, dict):
                block_time = block_data.get('blocked_at', datetime.now())
            else:
                block_time = block_data
            
            # Check if block has expired (24 hours)
            if datetime.now() - block_time > timedelta(hours=24):
                del self.blocked_ips[ip]
                return False
            return True
        return False
    
    async def _check_rate_limit(self, ip: str) -> bool:
        """Advanced rate limiting with burst detection and adaptive throttling"""
        now = datetime.now()

        if ip in {"127.0.0.1", "localhost", "::1"}:
            startup_grace = max(0, int(self.settings.rate_limit_localhost_startup_grace_seconds))
            if startup_grace and (now - self.started_at).total_seconds() < startup_grace:
                return True

        window_start = now - timedelta(seconds=self.settings.rate_limit_window)
        
        if ip not in self.rate_limits:
            self.rate_limits[ip] = []
        
        # Clean old requests outside the window
        self.rate_limits[ip] = [
            req_time for req_time in self.rate_limits[ip] 
            if req_time > window_start
        ]
        
        current_request_count = len(self.rate_limits[ip])
        
        # Burst detection - check for sudden spikes
        recent_window = now - timedelta(seconds=5)  # Last 5 seconds
        recent_requests = [req for req in self.rate_limits[ip] if req > recent_window]
        burst_threshold = self.settings.rate_limit_requests // 2  # 50% of limit in 5 seconds
        
        if len(recent_requests) >= burst_threshold:
            logger.warning(f"Burst attack detected from {ip}: {len(recent_requests)} requests in 5 seconds")
            # Temporarily block aggressive bursts
            await self._auto_block_ip(ip, "Burst attack - rapid request spike")
            return False
        
        # Progressive rate limiting - stricter limits as request count increases
        if current_request_count >= self.settings.rate_limit_requests:
            return False
        elif current_request_count >= (self.settings.rate_limit_requests * 0.8):
            # 80% threshold - start applying delays
            logger.info(f"IP {ip} approaching rate limit: {current_request_count}/{self.settings.rate_limit_requests}")
        
        # Distributed attack detection - check for coordinated attacks
        await self._detect_distributed_attack()
        
        # Add current request
        self.rate_limits[ip].append(now)
        return True
    
    async def _detect_distributed_attack(self):
        """Detect distributed DDoS attacks from multiple IPs"""
        now = datetime.now()
        recent_window = now - timedelta(seconds=10)
        
        # Count total requests across all IPs in last 10 seconds
        total_recent_requests = 0
        active_ips = 0
        
        for ip, requests in self.rate_limits.items():
            recent = [req for req in requests if req > recent_window]
            if recent:
                total_recent_requests += len(recent)
                active_ips += 1
        
        # DDoS threshold: 500+ requests from 10+ IPs in 10 seconds
        if total_recent_requests > 500 and active_ips >= 10:
            logger.critical(f"Distributed DDoS attack detected! {total_recent_requests} requests from {active_ips} IPs")
            # Trigger emergency mode (could notify admins, enable CAPTCHA, etc.)
            self.metrics.threats_detected += 1
        
        # Slowloris detection - many IPs with persistent connections
        if active_ips > 50:
            logger.warning(f"Potential Slowloris attack: {active_ips} concurrent connections")
    
    async def _detect_sql_injection(self, url: str, body: Optional[str]) -> List[str]:
        """Detect SQL injection patterns with multiple decoding passes"""
        import urllib.parse
        import html
        detected_patterns = []
        
        # Quick check: If it contains HTML tags (even URL-encoded), it's likely XSS not SQL - skip SQL detection
        combined = f"{url} {body or ''}"
        # Decode once to catch URL-encoded HTML tags
        decoded_combined = urllib.parse.unquote(combined)
        # Check for HTML tags in both original and decoded
        html_tag_pattern = r'</?[a-z]+[\s/>]'
        if re.search(html_tag_pattern, combined, re.IGNORECASE) or re.search(html_tag_pattern, decoded_combined, re.IGNORECASE):
            # Contains HTML tags - not SQL injection, likely XSS
            return []
        
        # Multiple decoding passes to catch nested encoding
        contents = []
        
        # Pass 1: Original
        contents.append(f"{url} {body or ''}")
        
        # Pass 2: Single URL decode
        decoded_url = urllib.parse.unquote_plus(url)
        decoded_body = urllib.parse.unquote_plus(body) if body else ''
        contents.append(f"{decoded_url} {decoded_body}")
        
        # Pass 3: Double URL decode
        double_decoded_url = urllib.parse.unquote_plus(decoded_url)
        double_decoded_body = urllib.parse.unquote_plus(decoded_body)
        contents.append(f"{double_decoded_url} {double_decoded_body}")
        
        # Pass 4: Triple URL decode (for extreme cases)
        triple_decoded_url = urllib.parse.unquote_plus(double_decoded_url)
        triple_decoded_body = urllib.parse.unquote_plus(double_decoded_body)
        contents.append(f"{triple_decoded_url} {triple_decoded_body}")
        
        # Pass 5: HTML entity decode
        html_decoded_url = html.unescape(triple_decoded_url)
        html_decoded_body = html.unescape(triple_decoded_body)
        contents.append(f"{html_decoded_url} {html_decoded_body}")
        
        # Normalize whitespace and remove SQL comments
        for i, content in enumerate(contents):
            # Remove multiple spaces
            content = re.sub(r'\s+', ' ', content)
            # Remove SQL block comments
            content = re.sub(r'/\*.*?\*/', ' ', content)
            # Remove SQL line comments
            content = re.sub(r'--[^\n]*', ' ', content)
            # Remove null bytes
            content = content.replace('\x00', '')
            # Lowercase for case-insensitive matching
            contents[i] = content.lower()
        
        # Check all decoded versions against patterns
        for content in contents:
            for pattern in self.sql_injection_patterns:
                try:
                    if pattern.search(content) and pattern.pattern not in detected_patterns:
                        detected_patterns.append(pattern.pattern)
                except Exception:
                    continue
        
        return detected_patterns
    
    async def _detect_xss(self, url: str, body: Optional[str]) -> List[str]:
        """Detect XSS patterns with multiple decoding passes"""
        import urllib.parse
        import html
        detected_patterns = []
        
        # Multiple decoding passes
        contents = []
        
        # Pass 1: Original
        contents.append(f"{url} {body or ''}")
        
        # Pass 2: Single URL decode
        decoded_url = urllib.parse.unquote_plus(url)
        decoded_body = urllib.parse.unquote_plus(body) if body else ''
        contents.append(f"{decoded_url} {decoded_body}")
        
        # Pass 3: Double URL decode
        double_decoded_url = urllib.parse.unquote_plus(decoded_url)
        double_decoded_body = urllib.parse.unquote_plus(decoded_body)
        contents.append(f"{double_decoded_url} {double_decoded_body}")
        
        # Pass 4: Triple URL decode
        triple_decoded_url = urllib.parse.unquote_plus(double_decoded_url)
        triple_decoded_body = urllib.parse.unquote_plus(double_decoded_body)
        contents.append(f"{triple_decoded_url} {triple_decoded_body}")
        
        # Pass 5: HTML entity decode
        html_decoded_url = html.unescape(triple_decoded_url)
        html_decoded_body = html.unescape(triple_decoded_body)
        contents.append(f"{html_decoded_url} {html_decoded_body}")
        
        # Pass 6: Remove spaces between tags and attributes (common obfuscation)
        for i, content in enumerate(contents):
            # Normalize whitespace
            content = re.sub(r'\s+', ' ', content)
            # Remove null bytes
            content = content.replace('\x00', '')
            # Remove Unicode zero-width characters
            content = content.replace('\u200b', '').replace('\ufeff', '')
            # Lowercase for better matching
            contents[i] = content.lower()
        
        # Check all decoded versions
        for content in contents:
            for pattern in self.xss_patterns:
                try:
                    if pattern.search(content) and pattern.pattern not in detected_patterns:
                        detected_patterns.append(pattern.pattern)
                except Exception:
                    continue
        
        return detected_patterns
    
    async def _detect_html_injection(self, url: str, body: Optional[str]) -> List[str]:
        """Detect HTML injection (harmless HTML tags without JavaScript execution)"""
        import urllib.parse
        import html
        detected_patterns = []
        
        # Multiple decoding passes
        contents = []
        
        # Pass 1: Original
        contents.append(f"{url} {body or ''}")
        
        # Pass 2: Single URL decode
        decoded_url = urllib.parse.unquote_plus(url)
        decoded_body = urllib.parse.unquote_plus(body) if body else ''
        contents.append(f"{decoded_url} {decoded_body}")
        
        # Pass 3: HTML entity decode
        html_decoded_url = html.unescape(decoded_url)
        html_decoded_body = html.unescape(decoded_body)
        contents.append(f"{html_decoded_url} {html_decoded_body}")
        
        # Check all decoded versions
        for content in contents:
            for pattern in self.html_injection_patterns:
                try:
                    if pattern.search(content) and pattern.pattern not in detected_patterns:
                        detected_patterns.append(pattern.pattern)
                except Exception:
                    continue
        
        return detected_patterns
    
    async def _detect_path_traversal(self, url: str, body: Optional[str]) -> List[str]:
        """Detect path traversal patterns with aggressive decoding"""
        import urllib.parse
        detected_patterns = []
        
        # Multiple decoding passes for path traversal
        contents = []
        
        # Pass 1: Original
        contents.append(f"{url} {body or ''}")
        
        # Pass 2: Single URL decode
        decoded_url = urllib.parse.unquote_plus(url)
        decoded_body = urllib.parse.unquote_plus(body) if body else ''
        contents.append(f"{decoded_url} {decoded_body}")
        
        # Pass 3: Double URL decode
        double_decoded_url = urllib.parse.unquote_plus(decoded_url)
        double_decoded_body = urllib.parse.unquote_plus(decoded_body)
        contents.append(f"{double_decoded_url} {double_decoded_body}")
        
        # Pass 4: Triple URL decode (path traversal often heavily encoded)
        triple_decoded_url = urllib.parse.unquote_plus(double_decoded_url)
        triple_decoded_body = urllib.parse.unquote_plus(double_decoded_body)
        contents.append(f"{triple_decoded_url} {triple_decoded_body}")
        
        # Pass 5: Quadruple decode (extreme cases)
        quad_decoded_url = urllib.parse.unquote_plus(triple_decoded_url)
        quad_decoded_body = urllib.parse.unquote_plus(triple_decoded_body)
        contents.append(f"{quad_decoded_url} {quad_decoded_body}")
        
        # Normalize paths
        for i, content in enumerate(contents):
            # Normalize slashes
            content = content.replace('\\', '/')
            # Remove null bytes
            content = content.replace('\x00', '')
            # Remove duplicate slashes
            content = re.sub(r'/+', '/', content)
            # Normalize backslashes to forward slashes for consistent matching
            content = content.replace('\\\\', '/')
            contents[i] = content.lower()
        
        # Check all decoded versions
        for content in contents:
            for pattern in self.path_traversal_patterns:
                try:
                    if pattern.search(content) and pattern.pattern not in detected_patterns:
                        detected_patterns.append(pattern.pattern)
                except Exception:
                    continue
        
        return detected_patterns
    
    async def _detect_bot(self, user_agent: str) -> Optional[str]:
        """Detect bot/crawler patterns"""
        for pattern in self.bot_patterns:
            if pattern.search(user_agent):
                return pattern.pattern.split('|')[0]  # Return first matching pattern
        return None
    
    async def _detect_command_injection(self, url: str, body: Optional[str]) -> List[str]:
        """Detect command injection patterns with multi-pass decoding"""
        import urllib.parse
        detected_patterns = []
        contents = self._multi_decode(url, body)
        
        for content in contents:
            for pattern in self.command_injection_patterns:
                try:
                    if pattern.search(content) and pattern.pattern not in detected_patterns:
                        detected_patterns.append(pattern.pattern)
                except Exception:
                    continue
        return detected_patterns
    
    async def _detect_auth_bypass(self, url: str, body: Optional[str]) -> List[str]:
        """Detect authentication bypass attempts in URL query parameters ONLY.
        
        This function checks for DANGEROUS authentication bypass patterns, not
        legitimate token-based authentication. Many apps use ?token= for auth.
        
        We only flag truly suspicious patterns like:
        - Session IDs in URLs (PHPSESSID, JSESSIONID, etc.)
        - Password in URL query strings
        - Admin privilege escalation (is_admin=true, role=admin)
        """
        import urllib.parse
        detected_patterns = []
        
        # Only detect DANGEROUS auth bypass patterns
        # Normal token/api_key in URL is legitimate for many apps
        auth_bypass_patterns = [
            # Session IDs should NEVER be in URLs (session fixation risk)
            re.compile(r'[?&](PHPSESSID|JSESSIONID|ASP\.NET_SessionId|session_id|sessionid)=', re.IGNORECASE),
            # Passwords should NEVER be in URLs
            re.compile(r'[?&](password|passwd|pwd)=', re.IGNORECASE),
            # Privilege escalation attempts
            re.compile(r'[?&](is_admin|isadmin|isAdmin)=(true|1|yes)', re.IGNORECASE),
            re.compile(r'[?&](role|user_role)=(admin|administrator|root|superuser)', re.IGNORECASE),
            re.compile(r'[?&](privilege|access_level)=(admin|elevated|root)', re.IGNORECASE),
            # JWT/Bearer tokens in URL are suspicious (should be in headers)
            re.compile(r'[?&](jwt|bearer|authorization)=eyJ', re.IGNORECASE),  # JWT tokens start with eyJ
        ]
        
        # ONLY check URL for authentication parameters - NOT the body
        # POST body with password= is normal for login forms
        contents = self._multi_decode(url, None)  # Pass None for body to ignore it
        
        for content in contents:
            for pattern in auth_bypass_patterns:
                try:
                    if pattern.search(content):
                        match = pattern.search(content)
                        if match:
                            detected_patterns.append(f"Suspicious auth parameter: {match.group(0)}")
                except Exception:
                    continue
        
        return detected_patterns
    
    async def _detect_ldap_injection(self, url: str, body: Optional[str]) -> List[str]:
        """Detect LDAP injection patterns"""
        import urllib.parse
        detected_patterns = []
        contents = self._multi_decode(url, body)
        
        for content in contents:
            for pattern in self.ldap_injection_patterns:
                try:
                    if pattern.search(content) and pattern.pattern not in detected_patterns:
                        detected_patterns.append(pattern.pattern)
                except Exception:
                    continue
        return detected_patterns
    
    async def _detect_xml_injection(self, url: str, body: Optional[str]) -> List[str]:
        """Detect XML/XXE injection patterns"""
        import urllib.parse
        detected_patterns = []
        contents = self._multi_decode(url, body)
        
        for content in contents:
            for pattern in self.xml_injection_patterns:
                try:
                    if pattern.search(content) and pattern.pattern not in detected_patterns:
                        detected_patterns.append(pattern.pattern)
                except Exception:
                    continue
        return detected_patterns
    
    async def _detect_ssrf(self, url: str, body: Optional[str]) -> List[str]:
        """Detect SSRF patterns - only check query parameters and body, not the URL path"""
        import urllib.parse
        detected_patterns = []
        
        # Parse URL to extract only query parameters
        parsed_url = urllib.parse.urlparse(url)
        query_string = parsed_url.query
        
        # Only check query parameters and body content, not the path or host
        # This prevents false positives when accessing localhost:5000/protected
        contents_to_check = []
        
        if query_string:
            contents_to_check.extend(self._multi_decode(query_string, None))
        
        if body:
            contents_to_check.extend(self._multi_decode("", body))
        
        # Check for SSRF patterns only in query params and body
        for content in contents_to_check:
            for pattern in self.ssrf_patterns:
                try:
                    if pattern.search(content) and pattern.pattern not in detected_patterns:
                        detected_patterns.append(pattern.pattern)
                except Exception:
                    continue
        return detected_patterns
    
    async def _detect_template_injection(self, url: str, body: Optional[str]) -> List[str]:
        """Detect template injection patterns"""
        import urllib.parse
        detected_patterns = []
        contents = self._multi_decode(url, body)
        
        for content in contents:
            for pattern in self.template_injection_patterns:
                try:
                    if pattern.search(content) and pattern.pattern not in detected_patterns:
                        detected_patterns.append(pattern.pattern)
                except Exception:
                    continue
        return detected_patterns
    
    async def _detect_rce(self, url: str, body: Optional[str]) -> List[str]:
        """Detect RCE patterns"""
        import urllib.parse
        detected_patterns = []
        contents = self._multi_decode(url, body)
        
        for content in contents:
            for pattern in self.rce_patterns:
                try:
                    if pattern.search(content) and pattern.pattern not in detected_patterns:
                        detected_patterns.append(pattern.pattern)
                except Exception:
                    continue
        return detected_patterns
    
    def _multi_decode(self, url: str, body: Optional[str]) -> List[str]:
        """Helper method for multiple decoding passes"""
        import urllib.parse
        import html
        contents = []
        
        # Pass 1: Original
        contents.append(f"{url} {body or ''}")
        
        # Pass 2-5: Progressive URL decoding
        decoded = f"{url} {body or ''}"
        for _ in range(4):
            decoded_url = urllib.parse.unquote_plus(decoded.split(' ')[0])
            decoded_body = urllib.parse.unquote_plus(' '.join(decoded.split(' ')[1:]))
            decoded = f"{decoded_url} {decoded_body}"
            contents.append(decoded)
        
        # Pass 6: HTML entity decode
        html_decoded = html.unescape(decoded)
        contents.append(html_decoded)
        
        # Normalize
        normalized = []
        for content in contents:
            content = re.sub(r'\s+', ' ', content)
            content = content.replace('\x00', '')
            content = content.replace('\u200b', '').replace('\ufeff', '')
            normalized.append(content.lower())
        
        return normalized
    
    async def _detect_ddos_patterns(self, method: str, url: str, headers: Dict[str, str], 
                                   user_agent: str, ip: str) -> Dict[str, Any]:
        """
        Advanced DDoS detection with multiple indicators
        Returns: {"score": int, "indicators": List[str]}
        Score >= 5 indicates likely DDoS attack
        """
        score = 0
        indicators = []
        now = datetime.now()
        
        # Whitelist localhost/loopback IPs from DDoS checks
        if ip in ['127.0.0.1', 'localhost', '::1', '0.0.0.0']:
            return {"score": 0, "indicators": ["Localhost whitelisted"]}
        
        # Initialize connection tracking for this IP
        if ip not in self.connection_table:
            self.connection_table[ip] = {
                "first_seen": now,
                "request_count": 0,
                "methods": set(),
                "unique_urls": set(),
                "user_agents": set()
            }
        
        conn = self.connection_table[ip]
        conn["request_count"] += 1
        conn["methods"].add(method)
        conn["unique_urls"].add(url)
        conn["user_agents"].add(user_agent)
        
        # 1. Empty or suspicious User-Agent (but allow legitimate browsers)
        if not user_agent or user_agent == "unknown" or user_agent == "-":
            score += 1
            indicators.append("Missing/empty User-Agent")
        elif user_agent and len(user_agent) < 10 and "Mozilla" not in user_agent:
            # Very short UA without browser signature
            score += 1
            indicators.append("Suspicious short User-Agent")
        
        # 2. Same User-Agent from many requests (botnet signature)
        if user_agent in self.user_agent_cache:
            self.user_agent_cache[user_agent] += 1
            if self.user_agent_cache[user_agent] > 100:  # Same UA 100+ times
                score += 1
                indicators.append(f"Repeated User-Agent ({self.user_agent_cache[user_agent]} times)")
        else:
            self.user_agent_cache[user_agent] = 1
        
        # 3. Suspicious request patterns
        # Same URL repeatedly (resource exhaustion)
        if ip in self.request_patterns:
            self.request_patterns[ip].append(url)
            # Keep only last 20 requests
            self.request_patterns[ip] = self.request_patterns[ip][-20:]
            
            # Check if hammering same endpoint
            if len(self.request_patterns[ip]) >= 10:
                unique_urls = len(set(self.request_patterns[ip]))
                if unique_urls <= 2:  # 10+ requests to same 1-2 URLs
                    score += 2
                    indicators.append(f"URL hammering: {unique_urls} unique URLs in {len(self.request_patterns[ip])} requests")
        else:
            self.request_patterns[ip] = [url]
        
        # 4. HTTP method flooding
        if len(conn["methods"]) > 1 and conn["request_count"] > 20:
            # Mixed methods in rapid succession (attack tool signature)
            score += 1
            indicators.append(f"Method variety: {len(conn['methods'])} different methods")
        
        # 5. Missing common headers (bot signature)
        suspicious_headers = 0
        if "accept" not in headers:
            suspicious_headers += 1
        if "accept-language" not in headers:
            suspicious_headers += 1
        if "accept-encoding" not in headers:
            suspicious_headers += 1
        
        if suspicious_headers >= 2:
            score += 1
            indicators.append(f"Missing {suspicious_headers} common headers")
        
        # 6. Unusual request frequency
        time_since_first = (now - conn["first_seen"]).total_seconds()
        if time_since_first > 0:
            requests_per_second = conn["request_count"] / time_since_first
            if requests_per_second > 10:  # More than 10 req/sec from single IP
                score += 2
                indicators.append(f"High frequency: {requests_per_second:.1f} req/sec")
        
        # 7. Slowloris detection - incomplete requests
        content_length = headers.get("content-length", "0")
        if method in ["POST", "PUT"] and content_length == "0":
            score += 1
            indicators.append("Incomplete POST/PUT request")
        
        # 8. Suspicious query strings (amplification attacks)
        if "?" in url:
            query_length = len(url.split("?", 1)[1])
            if query_length > 500:  # Very long query string
                score += 1
                indicators.append(f"Excessive query string length: {query_length} chars")
        
        # 9. Known attack tool signatures in User-Agent
        attack_tools = ["hping", "slowloris", "hulk", "rudy", "loic", "hoic", 
                       "slowhttptest", "torshammer", "pyloris", "thc-ssl-dos"]
        ua_lower = user_agent.lower()
        for tool in attack_tools:
            if tool in ua_lower:
                score += 3
                indicators.append(f"Attack tool detected: {tool}")
                break
        
        # 10. Connection header anomalies
        connection_header = headers.get("connection", "").lower()
        if "keep-alive" in connection_header and conn["request_count"] > 50:
            # Persistent connection with many requests (slow attack)
            score += 1
            indicators.append("Suspicious persistent connection pattern")
        
        # Clean up old connection data (keep last hour only)
        if (now - conn["first_seen"]).total_seconds() > 3600:
            self.connection_table[ip] = {
                "first_seen": now,
                "request_count": 1,
                "methods": {method},
                "unique_urls": {url},
                "user_agents": {user_agent}
            }
        
        return {"score": score, "indicators": indicators}
    
    async def _auto_block_ip(self, ip: str, reason: str):
        """Automatically block an IP address"""
        # Don't auto-block localhost for testing purposes
        if ip in ["127.0.0.1", "localhost", "::1"]:
            logger.info("Skipping auto-block for localhost", ip=ip, reason=reason)
            return
        
        # Check if auto IP blocking is enabled
        print(f"🔍 _auto_block_ip called: IP={ip}, reason={reason}, auto_ip_blocking={self.settings.auto_ip_blocking}")
        if not self.settings.auto_ip_blocking:
            logger.info("Auto IP blocking disabled - attack detected but IP not blocked", ip=ip, reason=reason)
            print(f"✅ Auto IP blocking is OFF - IP {ip} NOT added to blocklist")
            return
        
        self.blocked_ips[ip] = {
            'blocked_at': datetime.now(),
            'reason': reason,
            'reason_type': 'malicious',
            'attempts': 1
        }
        logger.warning("IP auto-blocked", ip=ip, reason=reason)
        print(f"🚫 Auto IP blocking is ON - IP {ip} ADDED to blocklist")
        # Audit the auto-block action (write log + optional webhook)
        try:
            await self._log_auto_block(ip, {
                "reason": reason,
                "source": "auto_block",
                "timestamp": datetime.now().isoformat()
            })
        except Exception:
            pass
    
    # Management methods
    async def block_ip(self, ip: str, reason: str = "Manual block", reason_type: str = "manual"):
        """Manually block an IP address with full details"""
        try:
            ipaddress.ip_address(ip)  # Validate IP
            self.blocked_ips[ip] = {
                'blocked_at': datetime.now(),
                'reason': reason,
                'reason_type': reason_type,
                'attempts': 1
            }
            logger.info("IP manually blocked", ip=ip, reason=reason)
            try:
                await self._log_auto_block(ip, {
                    "reason": reason,
                    "source": "manual_block",
                    "reason_type": reason_type,
                    "timestamp": datetime.now().isoformat()
                })
            except Exception:
                pass
            return True
        except ValueError:
            logger.error("Invalid IP address", ip=ip)
            return False

    async def _log_auto_block(self, ip: str, details: dict):
        """Append an audit record for auto/manual blocks and optionally send webhook."""
        try:
            import os, json
            # Choose log directory relative to project logs folder
            root = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', '..'))
            log_dir = os.path.join(root, 'logs')
            os.makedirs(log_dir, exist_ok=True)
            log_file = os.path.join(log_dir, 'auto_block_audit.log')

            record = {
                "ip": ip,
                "details": details
            }
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(record, default=str) + '\n')

            # Optional webhook notification if configured
            try:
                if getattr(self.settings, 'webhook_alerts_enabled', False) and getattr(self.settings, 'webhook_url', None):
                    import httpx
                    async def _post():
                        try:
                            await httpx.post(self.settings.webhook_url, json=record, timeout=5.0)
                        except Exception:
                            pass
                    try:
                        import asyncio
                        asyncio.create_task(_post())
                    except Exception:
                        pass
            except Exception:
                pass
        except Exception:
            pass

    async def log_auto_block(self, ip: str, details: dict):
        """Public wrapper to create an audit record (async)."""
        await self._log_auto_block(ip, details)
    
    async def unblock_ip(self, ip: str):
        """Unblock an IP address"""
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            logger.info("IP unblocked", ip=ip)
            return True
        return False
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get current WAF metrics"""
        return {
            "total_requests": self.metrics.total_requests,
            "blocked_requests": self.metrics.blocked_requests,
            "allowed_requests": self.metrics.allowed_requests,
            "threats_detected": self.metrics.threats_detected,
            "avg_response_time": round(self.metrics.avg_response_time, 3),
            "blocked_ips_count": len(self.blocked_ips),
            "active_rate_limits": len(self.rate_limits),
            "last_reset": self.metrics.last_reset.isoformat(),
            "uptime": str(datetime.now() - self.metrics.last_reset),
        }
    
    async def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent security events from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT event_id, timestamp, threat_type, threat_level, ip, 
                       url, user_agent, action, blocked, details
                FROM security_events
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            import json
            events = []
            for row in rows:
                events.append({
                    "event_id": row[0],
                    "timestamp": row[1],
                    "threat_type": row[2],
                    "threat_level": row[3],
                    "ip": row[4] or "",
                    "url": row[5],
                    "user_agent": row[6],
                    "action": row[7],
                    "blocked": bool(row[8]),
                    "details": json.loads(row[9]) if row[9] else {}
                })
            
            return events
        except Exception as e:
            logger.error("Failed to fetch events from database", error=str(e))
            # Fallback to in-memory events
            return [event.to_dict() for event in self.security_events[-limit:]]
    
    async def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """Get list of blocked IP addresses with full details"""
        blocked_list = []
        for ip, block_data in self.blocked_ips.items():
            # Handle both datetime objects and dicts
            if isinstance(block_data, dict):
                block_time = block_data.get('blocked_at', datetime.now())
                reason = block_data.get('reason', 'Unknown')
                reason_type = block_data.get('reason_type', 'manual')
                attempts = block_data.get('attempts', 1)
            else:
                # Old format: block_data is datetime
                block_time = block_data
                reason = 'Blocked'
                reason_type = 'manual'
                attempts = 1
            
            # Calculate if blocked today
            today = datetime.now().date()
            blocked_date = block_time.date() if isinstance(block_time, datetime) else today
            is_today = blocked_date == today
            
            blocked_list.append({
                "ip": ip,
                "reason": reason,
                "reason_type": reason_type,
                "blocked_at": block_time.isoformat() if isinstance(block_time, datetime) else str(block_time),
                "expires_at": (block_time + timedelta(hours=24)).isoformat() if isinstance(block_time, datetime) else "",
                "attempts": attempts,
                "country": "🌍 Unknown",
                "is_today": is_today
            })
        
        return blocked_list
    
    async def clear_all_blocked_ips(self) -> bool:
        """Clear all blocked IP addresses"""
        try:
            self.blocked_ips.clear()
            logger.info("All blocked IPs cleared")
            return True
        except Exception as e:
            logger.error(f"Failed to clear blocked IPs: {e}")
            return False
    
    async def reset_metrics(self):
        """Reset WAF metrics"""
        self.metrics.reset()
        logger.info("WAF metrics reset")
    
    async def clear_events(self):
        """Clear security events history"""
        self.security_events.clear()
        self.connection_table.clear()
        self.request_patterns.clear()
        self.user_agent_cache.clear()
        logger.info("Security events and DDoS tracking data cleared")
    
    def _init_database(self):
        """Initialize database and create security_events table if it doesn't exist"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create security_events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    threat_level TEXT NOT NULL,
                    ip TEXT,
                    url TEXT,
                    user_agent TEXT,
                    action TEXT NOT NULL,
                    blocked INTEGER NOT NULL,
                    details TEXT
                )
            ''')
            
            # Create index on timestamp for faster queries
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON security_events(timestamp DESC)
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Database initialized successfully", db_path=self.db_path)
        except Exception as e:
            logger.error("Failed to initialize database", error=str(e))
    
    def _update_ai_score(self, security_event: SecurityEvent):
        """Re-score event with AI after threat detection"""
        if getattr(self, "ai_scorer", None) is not None and security_event.threat_type != "none":
            try:
                ai_result = self.ai_scorer.score_event(security_event)
                security_event.details["ai"] = ai_result
            except Exception:
                pass
    
    def _log_event_to_db(self, security_event: SecurityEvent):
        """Log security event to database"""
        # Re-score with AI if threat was detected
        self._update_ai_score(security_event)
        
        try:
            print(f"💾 Logging event to DB: {security_event.threat_type} | {security_event.target_url}")
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            import json
            cursor.execute('''
                INSERT INTO security_events 
                (event_id, timestamp, threat_type, threat_level, ip, url, 
                 user_agent, action, blocked, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                security_event.id,
                security_event.timestamp.isoformat(),
                security_event.threat_type,
                security_event.threat_level.value,
                security_event.source_ip,
                security_event.target_url,
                security_event.user_agent,
                security_event.action_taken.value,
                1 if security_event.blocked else 0,
                json.dumps(security_event.details)
            ))
            
            conn.commit()
            conn.close()
            print(f"✅ Event logged successfully to {self.db_path}")

            if (
                getattr(self, "threatloom_integrator", None) is not None
                and getattr(self.settings, "threatloom_enabled", False)
                and (security_event.blocked or security_event.threat_type != "none")
            ):
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(self.threatloom_integrator.send_event(security_event))
                except RuntimeError:
                    logger.warning(
                        "ThreatLoom forwarding skipped because no running event loop was available",
                        event_id=security_event.id,
                    )
        except Exception as e:
            print(f"❌ Failed to log event: {e}")
            logger.error("Failed to log event to database", error=str(e), event_id=security_event.id)
