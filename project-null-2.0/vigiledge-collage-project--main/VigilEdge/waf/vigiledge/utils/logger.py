"""
Logging utilities for VigilEdge WAF
Configures structured logging for security events and monitoring
"""

import os
import sys
import logging
from datetime import datetime
from pathlib import Path

# Import structured logging if available
try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False
    structlog = None

from ..config import get_settings


def setup_logging():
    """Setup application logging configuration"""
    settings = get_settings()
    
    # Create logs directory if it doesn't exist
    log_file_path = Path(settings.log_file)
    log_file_path.parent.mkdir(parents=True, exist_ok=True)
    
    if STRUCTLOG_AVAILABLE:
        setup_structlog(settings)
    else:
        setup_standard_logging(settings)


def setup_structlog(settings):
    """Setup structured logging with structlog"""
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer() if settings.log_format == "json" else structlog.dev.ConsoleRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, settings.log_level.upper()),
    )
    
    # Add file handler if log file is specified
    if settings.log_file:
        file_handler = logging.FileHandler(settings.log_file)
        file_handler.setLevel(getattr(logging, settings.log_level.upper()))
        
        if settings.log_format == "json":
            formatter = logging.Formatter('%(message)s')
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        
        file_handler.setFormatter(formatter)
        logging.getLogger().addHandler(file_handler)


def setup_standard_logging(settings):
    """Setup standard Python logging"""
    log_level = getattr(logging, settings.log_level.upper())
    
    # Create formatters
    if settings.log_format == "json":
        class JSONFormatter(logging.Formatter):
            def format(self, record):
                import json
                log_entry = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "level": record.levelname,
                    "logger": record.name,
                    "message": record.getMessage(),
                    "module": record.module,
                    "function": record.funcName,
                    "line": record.lineno,
                }
                
                if record.exc_info:
                    log_entry["exception"] = self.formatException(record.exc_info)
                
                return json.dumps(log_entry)
        
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Add file handler if log file is specified
    if settings.log_file:
        file_handler = logging.FileHandler(settings.log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        logging.getLogger().addHandler(file_handler)


def get_logger(name: str):
    """Get a logger instance"""
    if STRUCTLOG_AVAILABLE:
        return structlog.get_logger(name)
    else:
        return logging.getLogger(name)


def log_security_event(event_type: str, details: dict, level: str = "info"):
    """Log a security event with structured data"""
    logger = get_logger("vigiledge.security")
    
    log_data = {
        "event_type": event_type,
        "timestamp": datetime.utcnow().isoformat(),
        **details
    }
    
    if level == "debug":
        logger.debug("Security event", **log_data)
    elif level == "info":
        logger.info("Security event", **log_data)
    elif level == "warning":
        logger.warning("Security event", **log_data)
    elif level == "error":
        logger.error("Security event", **log_data)
    elif level == "critical":
        logger.critical("Security event", **log_data)


def log_waf_decision(allowed: bool, threat_type: str, client_ip: str, url: str, details: dict = None):
    """Log WAF decision with relevant context"""
    logger = get_logger("vigiledge.waf")
    
    log_data = {
        "decision": "ALLOW" if allowed else "BLOCK",
        "threat_type": threat_type,
        "client_ip": client_ip,
        "url": url,
        "timestamp": datetime.utcnow().isoformat(),
    }
    
    if details:
        log_data.update(details)
    
    if allowed:
        logger.info("WAF decision", **log_data)
    else:
        logger.warning("WAF decision", **log_data)


def log_performance_metrics(operation: str, duration: float, details: dict = None):
    """Log performance metrics"""
    logger = get_logger("vigiledge.performance")
    
    log_data = {
        "operation": operation,
        "duration_ms": round(duration * 1000, 3),
        "timestamp": datetime.utcnow().isoformat(),
    }
    
    if details:
        log_data.update(details)
    
    logger.info("Performance metric", **log_data)


def log_admin_action(action: str, admin_user: str, details: dict = None):
    """Log administrative actions"""
    logger = get_logger("vigiledge.admin")
    
    log_data = {
        "action": action,
        "admin_user": admin_user,
        "timestamp": datetime.utcnow().isoformat(),
    }
    
    if details:
        log_data.update(details)
    
    logger.info("Admin action", **log_data)


class WAFLogger:
    """Centralized WAF logging class"""
    
    def __init__(self):
        self.security_logger = get_logger("vigiledge.security")
        self.waf_logger = get_logger("vigiledge.waf")
        self.performance_logger = get_logger("vigiledge.performance")
        self.admin_logger = get_logger("vigiledge.admin")
    
    def security_event(self, event_type: str, level: str, **kwargs):
        """Log security event"""
        getattr(self.security_logger, level)(event_type, **kwargs)
    
    def waf_decision(self, allowed: bool, **kwargs):
        """Log WAF decision"""
        level = "info" if allowed else "warning"
        getattr(self.waf_logger, level)("WAF decision", allowed=allowed, **kwargs)
    
    def performance(self, operation: str, duration: float, **kwargs):
        """Log performance metric"""
        self.performance_logger.info("Performance", 
                                   operation=operation, 
                                   duration_ms=round(duration * 1000, 3),
                                   **kwargs)
    
    def admin_action(self, action: str, admin_user: str, **kwargs):
        """Log admin action"""
        self.admin_logger.info("Admin action", 
                             action=action,
                             admin_user=admin_user,
                             **kwargs)


# Global logger instance
waf_logger = WAFLogger()
