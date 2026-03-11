"""
Settings Loader - Loads user settings from waf_settings.json at startup
Overrides default config.py settings with user-configured values
"""

import json
import logging
import os
from pathlib import Path
from typing import Dict, Any, Optional


logger = logging.getLogger(__name__)


class SettingsLoader:
    """Load and apply user settings from configuration file"""
    
    def __init__(self, settings_file: str = "config/waf_settings.json"):
        self.settings_file = Path(settings_file)
        self.user_settings: Optional[Dict[str, Any]] = None
        
    def load(self) -> Optional[Dict[str, Any]]:
        """Load settings from file"""
        try:
            if self.settings_file.exists():
                with open(self.settings_file, 'r') as f:
                    self.user_settings = json.load(f)
                logger.info(f"Loaded user settings from {self.settings_file}")
                return self.user_settings
            else:
                logger.warning(f"Settings file not found: {self.settings_file}, using defaults")
                return None
        except Exception as e:
            logger.error(f"Error loading settings: {e}")
            return None
    
    def get_network_settings(self) -> Dict[str, Any]:
        """Get network configuration settings"""
        if not self.user_settings:
            return {}
        
        network = self.user_settings.get("network", {})
        return {
            "listen_port": network.get("listen_port", 8000),
            "max_connections": network.get("max_connections", 1000),
            "ssl_enabled": network.get("ssl_enabled", False),
            "ssl_cert_path": network.get("ssl_cert_path", ""),
            "ssl_key_path": network.get("ssl_key_path", ""),
            "allowed_origins": network.get("allowed_origins", [])
        }
    
    def get_logging_settings(self) -> Dict[str, Any]:
        """Get logging configuration settings"""
        if not self.user_settings:
            return {}
        
        logging_config = self.user_settings.get("logging", {})
        return {
            "log_level": logging_config.get("log_level", "INFO"),
            "log_to_file": logging_config.get("log_to_file", True),
            "log_file_path": logging_config.get("log_file_path", "./logs/vigiledge.log"),
            "max_log_size_mb": logging_config.get("max_log_size_mb", 100),
            "log_retention_days": logging_config.get("log_retention_days", 30),
            "compress_old_logs": logging_config.get("compress_old_logs", True)
        }
    
    def get_security_settings(self) -> Dict[str, Any]:
        """Get security configuration settings"""
        if not self.user_settings:
            return {}
        
        security = self.user_settings.get("security", {})
        return {
            "threat_detection_enabled": security.get("threat_detection_enabled", True),
            "auto_block_ips": security.get("auto_block_ips", True),
            "rate_limiting": security.get("rate_limiting", True),
            "rate_limit_value": security.get("rate_limit_value", 100),
            "block_duration": security.get("block_duration", 60),
            "threat_sensitivity": security.get("threat_sensitivity", "medium")
        }
    
    def get_backup_settings(self) -> Dict[str, Any]:
        """Get backup configuration settings"""
        if not self.user_settings:
            return {}
        
        backup = self.user_settings.get("backup", {})
        return {
            "auto_backup": backup.get("auto_backup", False),
            "backup_frequency": backup.get("backup_frequency", "daily")
        }

    def get_upstream_settings(self) -> Dict[str, Any]:
        """Get upstream website routing settings."""
        if not self.user_settings:
            return {}

        upstream = self.user_settings.get("upstream", {})
        return {
            "use_demo_target": upstream.get("use_demo_target", False),
            "custom_target_url": upstream.get("custom_target_url", "http://localhost:3000"),
            "demo_target_url": upstream.get("demo_target_url", "http://localhost:8080"),
            "public_mode": upstream.get("public_mode", "both"),
            "public_subpath": upstream.get("public_subpath", "/protected"),
        }
    
    def get_rules_settings(self) -> Dict[str, Any]:
        """Get security rules settings"""
        if not self.user_settings:
            return {}
        
        return self.user_settings.get("rules", {})
    
    def get_auth_settings(self) -> Dict[str, Any]:
        """Get authentication settings"""
        if not self.user_settings:
            return {}
        
        auth = self.user_settings.get("authentication", {})
        return {
            "admin_password": auth.get("admin_password"),
            "admin_username": auth.get("admin_username")
        }
    
    def apply_to_app_settings(self, app_settings):
        """Apply user settings to application Settings object"""
        try:
            # Apply network settings
            network = self.get_network_settings()
            if network:
                app_settings.port = network.get("listen_port", app_settings.port)
                app_settings.host = "0.0.0.0"  # Listen on all interfaces
                logger.info(f"Network: port={app_settings.port}, max_connections={network.get('max_connections')}")
            
            # Apply logging settings
            logging_config = self.get_logging_settings()
            if logging_config:
                app_settings.log_level = logging_config.get("log_level", app_settings.log_level)
                logger.info(f"Logging: level={app_settings.log_level}, file={logging_config.get('log_file_path')}")
            
            # Apply security settings
            security = self.get_security_settings()
            if security:
                app_settings.rate_limit_requests = security.get("rate_limit_value", app_settings.rate_limit_requests)
                app_settings.rate_limit_enabled = security.get("rate_limiting", app_settings.rate_limit_enabled)
                # Apply auto IP blocking setting (maps auto_block_ips from JSON -> auto_ip_blocking in Settings)
                app_settings.auto_ip_blocking = security.get("auto_block_ips", app_settings.auto_ip_blocking)
                logger.info(f"Security: rate_limit={app_settings.rate_limit_requests}, auto_ip_blocking={app_settings.auto_ip_blocking}")
            
            # Apply auth settings
            auth = self.get_auth_settings()
            if auth:
                if auth.get("admin_password"):
                    app_settings.admin_password = auth.get("admin_password")
                if auth.get("admin_username"):
                    app_settings.admin_username = auth.get("admin_username")

            upstream = self.get_upstream_settings()
            if upstream:
                app_settings.upstream_use_demo_target = upstream.get("use_demo_target", app_settings.upstream_use_demo_target)
                app_settings.upstream_demo_target_url = upstream.get("demo_target_url", app_settings.upstream_demo_target_url)
                app_settings.upstream_custom_target_url = upstream.get("custom_target_url", app_settings.upstream_custom_target_url)
                app_settings.upstream_public_mode = upstream.get("public_mode", app_settings.upstream_public_mode)
                app_settings.vulnerable_app_proxy_path = upstream.get("public_subpath", app_settings.vulnerable_app_proxy_path)
                app_settings.vulnerable_app_url = (
                    app_settings.upstream_demo_target_url
                    if app_settings.upstream_use_demo_target
                    else app_settings.upstream_custom_target_url
                )

            env_demo_mode = os.getenv("UPSTREAM_USE_DEMO_TARGET")
            if env_demo_mode is not None:
                app_settings.upstream_use_demo_target = env_demo_mode.lower() in {"1", "true", "yes", "on"}

            env_custom_target = os.getenv("UPSTREAM_CUSTOM_TARGET_URL")
            if env_custom_target:
                app_settings.upstream_custom_target_url = env_custom_target

            env_demo_target = os.getenv("UPSTREAM_DEMO_TARGET_URL")
            if env_demo_target:
                app_settings.upstream_demo_target_url = env_demo_target

            env_public_mode = os.getenv("UPSTREAM_PUBLIC_MODE")
            if env_public_mode:
                app_settings.upstream_public_mode = env_public_mode

            env_proxy_path = os.getenv("VULNERABLE_APP_PROXY_PATH")
            if env_proxy_path:
                app_settings.vulnerable_app_proxy_path = env_proxy_path

            env_upstream_url = os.getenv("VULNERABLE_APP_URL")
            if env_upstream_url:
                app_settings.vulnerable_app_url = env_upstream_url
            else:
                app_settings.vulnerable_app_url = (
                    app_settings.upstream_demo_target_url
                    if app_settings.upstream_use_demo_target
                    else app_settings.upstream_custom_target_url
                )
            
            logger.info("User settings applied successfully")
            return True
        except Exception as e:
            logger.error(f"❌ Error applying settings: {e}")
            return False


# Global settings loader instance
_settings_loader = None


def get_settings_loader() -> SettingsLoader:
    """Get or create global settings loader instance"""
    global _settings_loader
    if _settings_loader is None:
        _settings_loader = SettingsLoader()
        _settings_loader.load()
    return _settings_loader


def load_user_settings():
    """Load user settings and return the loader instance"""
    loader = get_settings_loader()
    return loader
