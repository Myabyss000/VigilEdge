"""
Application configuration loaded from environment / .env file.
"""
from pathlib import Path
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "ThreatLoom"
    APP_ENV: str = "development"
    APP_DEBUG: bool = True
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8443
    SECRET_KEY: str = "change-this-to-a-random-secret-key-min-32-chars"

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./threatloom.db"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # JWT
    JWT_SECRET: str = "change-this-jwt-secret-min-32-chars"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_MINUTES: int = 480

    # GeoIP
    GEOIP_DB_PATH: str = "./data/GeoLite2-City.mmdb"

    # Retention (days)
    RETENTION_HOT_DAYS: int = 7
    RETENTION_WARM_DAYS: int = 30
    RETENTION_COLD_DAYS: int = 365

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "./logs/threatloom.log"

    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8443"]

    # Firewall integration (webhook callback)
    FIREWALL_WEBHOOK_URL: str = ""
    FIREWALL_WEBHOOK_SECRET: str = ""
    FIREWALL_WEBHOOK_ENABLED: bool = False

    # Notifications
    NOTIFICATIONS_ENABLED: bool = True
    NOTIFICATION_MIN_SEVERITY: str = "HIGH"
    NOTIFICATION_WEBHOOK_URL: str = ""
    NOTIFICATION_WEBHOOK_SECRET: str = ""
    BROWSER_NOTIFICATIONS_ENABLED: bool = True
    NOTIFICATION_EMAIL_ENABLED: bool = False
    NOTIFICATION_EMAIL_TO: str = ""
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = ""
    SMTP_USE_TLS: bool = True

    # Detection engine
    DETECTION_SCAN_INTERVAL_SECONDS: int = 3
    DETECTION_LOOKBACK_SECONDS: int = 15

    # Firewall health check
    FIREWALL_HEALTH_URL: str = "http://localhost:5000"
    FIREWALL_STARTUP_CHECK: bool = True
    FIREWALL_STARTUP_RETRIES: int = 5
    FIREWALL_STARTUP_RETRY_DELAY: int = 3

    # Rate Limiting
    RATE_LIMIT_DEFAULT: str = "100/minute"

    # Default admin
    DEFAULT_ADMIN_USER: str = "admin"
    DEFAULT_ADMIN_PASS: str = "changeme"

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
