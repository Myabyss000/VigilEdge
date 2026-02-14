"""
Windows Defender Integration for VigilEdge WAF
Logs security events to Windows Event Log for Windows Security Center visibility
"""

import subprocess
import logging
import json
from datetime import datetime
from typing import Optional, Dict, Any
from enum import Enum

logger = logging.getLogger(__name__)


class EventSeverity(Enum):
    """Windows Event Log severity levels"""
    INFORMATION = "Information"
    WARNING = "Warning"
    ERROR = "Error"


class WindowsDefenderIntegration:
    """
    Integrates VigilEdge WAF with Windows Defender/Security Center
    by logging security events to Windows Event Log.
    """
    
    # Event source name for Windows Event Log
    EVENT_SOURCE = "VigilEdge-WAF"
    EVENT_LOG = "Application"
    
    # Threat type to severity mapping
    THREAT_SEVERITY_MAP = {
        "sql_injection": EventSeverity.ERROR,
        "xss_attempt": EventSeverity.ERROR,
        "path_traversal": EventSeverity.ERROR,
        "command_injection": EventSeverity.ERROR,
        "ddos_attack": EventSeverity.ERROR,
        "rate_limit_exceeded": EventSeverity.WARNING,
        "blocked_ip": EventSeverity.WARNING,
        "auth_bypass_attempt": EventSeverity.ERROR,
        "ldap_injection": EventSeverity.ERROR,
        "xml_injection": EventSeverity.ERROR,
        "ssrf_attempt": EventSeverity.ERROR,
        "template_injection": EventSeverity.ERROR,
        "html_injection": EventSeverity.WARNING,
    }
    
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._check_event_source()
    
    def _check_event_source(self):
        """Check if event source exists, create if needed (requires admin)"""
        try:
            # Try to create the event source using PowerShell
            # This only needs to run once (requires admin privileges)
            ps_script = f'''
            if (-not [System.Diagnostics.EventLog]::SourceExists("{self.EVENT_SOURCE}")) {{
                try {{
                    [System.Diagnostics.EventLog]::CreateEventSource("{self.EVENT_SOURCE}", "{self.EVENT_LOG}")
                    Write-Host "Created event source: {self.EVENT_SOURCE}"
                }} catch {{
                    Write-Host "Could not create event source (need admin): $_"
                }}
            }} else {{
                Write-Host "Event source already exists: {self.EVENT_SOURCE}"
            }}
            '''
            result = subprocess.run(
                ["powershell", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=5
            )
            logger.info(f"Event source check: {result.stdout.strip()}")
        except Exception as e:
            logger.warning(f"Could not check/create event source: {e}")
    
    def log_security_event(
        self,
        event_id: str,
        threat_type: str,
        threat_level: str,
        source_ip: str,
        target_url: str,
        blocked: bool,
        details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Log a security event to Windows Event Log.
        
        Args:
            event_id: Unique event identifier
            threat_type: Type of threat detected
            threat_level: Severity level (low, medium, high, critical)
            source_ip: IP address of the attacker
            target_url: URL that was targeted
            blocked: Whether the request was blocked
            details: Additional event details
            
        Returns:
            True if event was logged successfully
        """
        if not self.enabled:
            return False
        
        try:
            # Determine Windows Event severity
            severity = self.THREAT_SEVERITY_MAP.get(
                threat_type.lower(), 
                EventSeverity.WARNING
            )
            
            # Build event message
            status = "BLOCKED" if blocked else "DETECTED"
            message = self._format_event_message(
                event_id=event_id,
                threat_type=threat_type,
                threat_level=threat_level,
                source_ip=source_ip,
                target_url=target_url,
                status=status,
                details=details
            )
            
            # Log to Windows Event Log using PowerShell
            return self._write_event_log(message, severity)
            
        except Exception as e:
            logger.error(f"Failed to log security event to Windows: {e}")
            return False
    
    def _format_event_message(
        self,
        event_id: str,
        threat_type: str,
        threat_level: str,
        source_ip: str,
        target_url: str,
        status: str,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """Format the event message for Windows Event Log"""
        timestamp = datetime.now().isoformat()
        
        message = f"""VigilEdge WAF Security Alert
========================================
Status: {status}
Event ID: {event_id}
Timestamp: {timestamp}

Threat Information:
- Type: {threat_type.upper().replace('_', ' ')}
- Level: {threat_level.upper()}
- Source IP: {source_ip}
- Target URL: {target_url}

Action Taken: Request {status}
"""
        
        if details:
            # Add detected patterns if available
            patterns = details.get("detected_patterns", [])
            if patterns:
                message += f"\nDetected Patterns:\n"
                for pattern in patterns[:5]:  # Limit to 5 patterns
                    message += f"  - {pattern}\n"
            
            # Add AI analysis if available
            ai_info = details.get("ai", {})
            if ai_info:
                ai_score = ai_info.get("ai_score", "N/A")
                message += f"\nAI Analysis Score: {ai_score}\n"
        
        message += """
========================================
For more details, check the VigilEdge WAF Dashboard.
"""
        return message
    
    def _write_event_log(self, message: str, severity: EventSeverity) -> bool:
        """Write event to Windows Event Log using PowerShell"""
        try:
            # Escape special characters for PowerShell
            escaped_message = message.replace("'", "''").replace('"', '`"')
            
            # Map severity to Windows event type
            event_type_map = {
                EventSeverity.INFORMATION: "Information",
                EventSeverity.WARNING: "Warning",
                EventSeverity.ERROR: "Error"
            }
            event_type = event_type_map.get(severity, "Warning")
            
            # PowerShell command to write event log
            ps_command = f'''
            Write-EventLog -LogName "{self.EVENT_LOG}" -Source "{self.EVENT_SOURCE}" -EventId 1000 -EntryType {event_type} -Message '{escaped_message}'
            '''
            
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                logger.debug(f"Security event logged to Windows Event Log")
                return True
            else:
                # Fallback: Try using eventcreate command (doesn't require pre-registered source)
                return self._write_event_log_fallback(message, severity)
                
        except Exception as e:
            logger.warning(f"PowerShell event log failed: {e}, trying fallback")
            return self._write_event_log_fallback(message, severity)
    
    def _write_event_log_fallback(self, message: str, severity: EventSeverity) -> bool:
        """Fallback method - write to local log file if Windows Event Log is not accessible"""
        try:
            # Try eventcreate first
            truncated_message = message[:1000] if len(message) > 1000 else message
            truncated_message = truncated_message.replace('"', "'").replace('\n', ' | ')
            
            type_map = {
                EventSeverity.INFORMATION: "INFORMATION",
                EventSeverity.WARNING: "WARNING",
                EventSeverity.ERROR: "ERROR"
            }
            event_type = type_map.get(severity, "WARNING")
            
            result = subprocess.run(
                [
                    "eventcreate",
                    "/T", event_type,
                    "/ID", "1000",
                    "/L", "APPLICATION",
                    "/SO", "VigilEdge-WAF",
                    "/D", truncated_message
                ],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                return True
            
            # If eventcreate fails (no admin rights), write to local security log file
            # This file can be viewed by Windows Security Center or SIEM tools
            return self._write_to_security_log_file(message, severity)
            
        except Exception as e:
            logger.warning(f"Event log failed: {e}, writing to local file")
            return self._write_to_security_log_file(message, severity)
    
    def _write_to_security_log_file(self, message: str, severity: EventSeverity) -> bool:
        """Write security events to a local log file for integration with security tools"""
        try:
            import os
            from datetime import datetime
            
            # Create logs directory if it doesn't exist
            log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
            os.makedirs(log_dir, exist_ok=True)
            
            # Security event log file
            log_file = os.path.join(log_dir, "windows_security_events.log")
            
            # Format the log entry
            timestamp = datetime.now().isoformat()
            severity_str = severity.value.upper()
            
            log_entry = f"[{timestamp}] [{severity_str}] {self.EVENT_SOURCE}\n"
            log_entry += "-" * 60 + "\n"
            log_entry += message + "\n"
            log_entry += "=" * 60 + "\n\n"
            
            # Append to log file
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(log_entry)
            
            logger.debug(f"Security event logged to {log_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to write security log file: {e}")
            return False
    
    def log_waf_started(self):
        """Log that WAF has started"""
        if not self.enabled:
            return
        
        message = """VigilEdge WAF Service Started
========================================
The VigilEdge Web Application Firewall has started.

Protection Status: ACTIVE
- SQL Injection Protection: Enabled
- XSS Protection: Enabled
- Path Traversal Protection: Enabled
- DDoS Protection: Enabled
- Rate Limiting: Enabled

Dashboard: http://127.0.0.1:5000
========================================
"""
        self._write_event_log(message, EventSeverity.INFORMATION)
    
    def log_waf_stopped(self):
        """Log that WAF has stopped"""
        if not self.enabled:
            return
        
        message = """VigilEdge WAF Service Stopped
========================================
The VigilEdge Web Application Firewall has stopped.

Protection Status: INACTIVE

Please restart the service for continued protection.
========================================
"""
        self._write_event_log(message, EventSeverity.WARNING)


# Global instance
_defender_integration: Optional[WindowsDefenderIntegration] = None


def get_defender_integration() -> WindowsDefenderIntegration:
    """Get or create the Windows Defender integration instance"""
    global _defender_integration
    if _defender_integration is None:
        _defender_integration = WindowsDefenderIntegration(enabled=True)
    return _defender_integration


def log_threat_to_defender(security_event) -> bool:
    """
    Convenience function to log a SecurityEvent to Windows Defender.
    
    Args:
        security_event: SecurityEvent object from waf_engine
        
    Returns:
        True if logged successfully
    """
    try:
        integration = get_defender_integration()
        return integration.log_security_event(
            event_id=security_event.id,
            threat_type=security_event.threat_type,
            threat_level=security_event.threat_level.value if hasattr(security_event.threat_level, 'value') else str(security_event.threat_level),
            source_ip=security_event.source_ip,
            target_url=security_event.target_url,
            blocked=security_event.blocked,
            details=security_event.details
        )
    except Exception as e:
        logger.error(f"Failed to log threat to Windows Defender: {e}")
        return False
