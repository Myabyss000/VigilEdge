"""
Centralised logging for ThreatLoom.

Configures one rotating file handler + one console handler on the root
"threatloom" logger so every module that calls
    logging.getLogger("threatloom.something")
automatically inherits the same handlers and format.

Usage
-----
Call setup_logging() exactly once, early in the application lifespan (before
any other import that logs).  Existing code that does
    logging.getLogger("threatloom")
requires zero changes.
"""
import json
import logging
import logging.handlers
import sys
from datetime import datetime, timezone
from pathlib import Path

from threatloom.config import settings

_LOG_RETENTION_DAYS = 30    # keep 30 daily log files
_LOG_MAX_BYTES = 50 * 1024 * 1024   # 50 MB before forced rotation (safety cap)


class _StructuredFormatter(logging.Formatter):
    """
    JSON formatter for structured / machine-readable log lines.
    Each line is a self-contained JSON object — easy to ship to a SIEM.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_obj: dict = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info:
            log_obj["exc"] = self.formatException(record.exc_info)
        # Attach any extra keyword args passed as `extra={"event_type": ...}`
        for key, value in record.__dict__.items():
            if key not in (
                "args", "asctime", "created", "exc_info", "exc_text", "filename",
                "funcName", "id", "levelname", "levelno", "lineno", "module",
                "msecs", "message", "msg", "name", "pathname", "process",
                "processName", "relativeCreated", "stack_info", "thread",
                "threadName", "taskName",
            ):
                log_obj[key] = value
        return json.dumps(log_obj, default=str)


def setup_logging() -> None:
    """
    Initialise the "threatloom" logger hierarchy with:
      - A TimedRotatingFileHandler (daily, 30-day retention)
      - A StreamHandler to stdout
    Safe to call more than once — duplicate handlers are not added.
    """
    root_logger = logging.getLogger("threatloom")
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    root_logger.setLevel(log_level)

    # ── avoid adding handlers twice (e.g. during uvicorn --reload) ───────────
    if root_logger.handlers:
        return

    use_json = getattr(settings, "LOG_FORMAT", "text").lower() == "json"

    # ── file handler (rotating, daily, 30-day retention) ─────────────────────
    log_path = Path(settings.LOG_FILE)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    file_handler = logging.handlers.TimedRotatingFileHandler(
        filename=str(log_path),
        when="midnight",
        interval=1,
        backupCount=_LOG_RETENTION_DAYS,
        encoding="utf-8",
        utc=True,
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(
        _StructuredFormatter() if use_json
        else logging.Formatter(
            "%(asctime)s | %(name)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
    )
    file_handler.suffix = "%Y-%m-%d"

    # ── console handler ───────────────────────────────────────────────────────
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(
        _StructuredFormatter() if use_json
        else logging.Formatter(
            "%(asctime)s | %(name)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
    )

    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    root_logger.propagate = False   # don't double-log via root logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the 'threatloom' hierarchy."""
    return logging.getLogger(f"threatloom.{name}" if not name.startswith("threatloom") else name)
