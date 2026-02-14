"""
Settings API Routes for VigilEdge WAF
Handles WAF configuration, backup management, and rule toggling.
"""

import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Response, Request
from fastapi.responses import JSONResponse

from .auth import check_auth

router = APIRouter(prefix="/api/v1", tags=["Settings"])


def get_waf_engine(request: Request = None):
    """Get WAF engine from app state."""
    if request:
        return request.app.state.waf_engine
    # Fallback to import if request is not available (though it should be for routes)
    from app import waf_engine
    return waf_engine


@router.post("/auth/change-password")
async def change_password(request: Request):
    """Change admin password."""
    if not check_auth(request):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        body = await request.json()
        current_password = body.get("current_password")
        new_password = body.get("new_password")
        
        if not current_password or not new_password:
            raise HTTPException(status_code=400, detail="Missing current or new password")
        
        waf_engine = get_waf_engine(request)
        settings = waf_engine.settings
        
        # Validate current password
        # Note: settings.admin_password might come from env var (config.py) if not overridden yet
        if current_password != settings.admin_password:
             raise HTTPException(status_code=400, detail="Incorrect current password")
             
        # Load existing settings file to update it
        settings_file = Path("config/waf_settings.json")
        user_settings = {}
        if settings_file.exists():
            with open(settings_file, 'r') as f:
                user_settings = json.load(f)
        else:
            # Initialize with defaults if missing, but we need structure
            user_settings = DEFAULT_SETTINGS.copy()
            
        # Update password in settings file
        if "authentication" not in user_settings:
            user_settings["authentication"] = {}
            
        user_settings["authentication"]["admin_password"] = new_password
        # Preserve existing username or default
        if "admin_username" not in user_settings["authentication"]:
             user_settings["authentication"]["admin_username"] = settings.admin_username

        # Save to file
        settings_file.parent.mkdir(parents=True, exist_ok=True)
        with open(settings_file, 'w') as f:
            json.dump(user_settings, f, indent=2)
            
        # Update in-memory settings immediately
        settings.admin_password = new_password
        
        # CRITICAL FIX: Also update the app state settings accessed by auth.py
        if request and hasattr(request.app.state, "settings"):
             request.app.state.settings.admin_password = new_password
             logging.info(f"Updated app.state.settings.admin_password to new value")
        
        return {"status": "success", "message": "Password updated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error changing password: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to change password: {str(e)}")


# Default settings template
DEFAULT_SETTINGS = {
    "security": {
        "threat_detection_enabled": True,
        "auto_block_ips": True,
        "rate_limiting": True,
        "rate_limit_value": 100,
        "block_duration": 60,
        "threat_sensitivity": "medium"
    },
    "network": {
        "listen_port": 8000,
        "max_connections": 1000,
        "ssl_enabled": True,
        "ssl_cert_path": "/certs/server.crt",
        "ssl_key_path": "/certs/server.key",
        "allowed_origins": ["https://localhost:8000", "https://127.0.0.1:8000"]
    },
    "logging": {
        "log_level": "INFO",
        "log_to_file": True,
        "log_file_path": "./logs/vigiledge.log",
        "max_log_size_mb": 100,
        "log_retention_days": 30,
        "compress_old_logs": True
    },
    "rules": {
        "sql_injection": True,
        "xss_protection": True,
        "path_traversal": True,
        "bot_detection": True,
        "command_injection": False
    },
    "backup": {
        "auto_backup": True,
        "backup_frequency": "daily"
    },
    "theme": {
        "selected_theme": "dark",
        "auto_dark_mode": False
    },
    "authentication": {
        "admin_username": "admin",
        "admin_password": None
    }
}


@router.get("/settings")
async def get_settings(request: Request):
    """Get all WAF settings from configuration file."""
    if not check_auth(request):
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        settings_file = Path("config/waf_settings.json")
        if settings_file.exists():
            with open(settings_file, 'r') as f:
                settings = json.load(f)
        else:
            settings = DEFAULT_SETTINGS.copy()
            
        # SECURITY: Never return the password in the settings payload
        if "authentication" in settings:
            settings["authentication"]["admin_password"] = None
            
        return settings
    except Exception as e:
        logging.error(f"Error loading settings: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to load settings: {str(e)}")


@router.post("/settings")
async def save_settings(request: Request):
    """Save WAF settings to configuration file."""
    if not check_auth(request):
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        settings = await request.json()
        
        # SECURITY: Prevent save_settings from modifying password
        # Password changes must go through /change-password endpoint
        if "authentication" in settings:
            # We explicitly remove it from the incoming payload so the merge logic below
            # (which looks for missing password) will kick in and preserve the file's value.
            if "admin_password" in settings["authentication"]:
                del settings["authentication"]["admin_password"]
        
        waf_engine = get_waf_engine(request)
        settings_file = Path("config/waf_settings.json")
        settings_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Validate settings structure
        required_sections = ["security", "network", "logging", "rules", "backup", "theme", "authentication"]
        for section in required_sections:
            if section not in settings:
                raise HTTPException(status_code=400, detail=f"Missing required section: {section}")
        
        # MERGE STRATEGY: Preserve sensitive data (passwords) not found in request
        if settings_file.exists():
            try:
                with open(settings_file, 'r') as f:
                    existing = json.load(f)
                    
                # 1. Preserve Password if not in payload
                if "authentication" in existing:
                    payload_auth = settings.get("authentication", {})
                    existing_auth = existing["authentication"]
                    
                    if not payload_auth.get("admin_password") and existing_auth.get("admin_password"):
                        if "authentication" not in settings:
                            settings["authentication"] = {}
                        settings["authentication"]["admin_password"] = existing_auth["admin_password"]
                        logging.info("Preserved existing admin_password during settings save")
                        
                    # Preserve username if missing too
                    if not payload_auth.get("admin_username") and existing_auth.get("admin_username"):
                        settings["authentication"]["admin_username"] = existing_auth["admin_username"]
                        
            except Exception as e:
                logging.error(f"Error merging existing settings: {e}")

        # Save to file
        with open(settings_file, 'w') as f:
            json.dump(settings, f, indent=2)
        
        # Apply settings to WAF engine in real-time
        try:
            if settings["security"]["rate_limiting"]:
                waf_engine.rate_limit = settings["security"]["rate_limit_value"]
            
            waf_engine.threat_sensitivity = settings["security"]["threat_sensitivity"]
            
            # Apply auto IP blocking setting to WAF engine
            if "auto_block_ips" in settings["security"]:
                waf_engine.settings.auto_ip_blocking = settings["security"]["auto_block_ips"]
                logging.info(f"Auto IP blocking set to: {waf_engine.settings.auto_ip_blocking}")
            
            for rule_name, enabled in settings["rules"].items():
                if hasattr(waf_engine, f"{rule_name}_enabled"):
                    setattr(waf_engine, f"{rule_name}_enabled", enabled)
            
            logging.info("Settings saved and applied successfully")
        except Exception as e:
            logging.warning(f"Settings saved but failed to apply: {e}")
        
        return {
            "status": "success",
            "message": "Settings saved successfully",
            "timestamp": datetime.now().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error saving settings: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to save settings: {str(e)}")


@router.post("/settings/reset")
async def reset_settings(request: Request):
    """Reset settings to factory defaults by deleting the config file."""
    if not check_auth(request):
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        settings_file = Path("config/waf_settings.json")
        
        # Create backup before resetting
        if settings_file.exists():
            backup_dir = Path("backups")
            backup_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = backup_dir / f"before_reset_{timestamp}.json"
            
            with open(settings_file, 'r') as f:
                current_settings = f.read()
            with open(backup_path, 'w') as f:
                f.write(current_settings)
            
            settings_file.unlink()
            logging.info("Settings reset to defaults (config file deleted)")
        
        return {
            "status": "success",
            "message": "Settings reset to factory defaults",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logging.error(f"Error resetting settings: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to reset settings: {str(e)}")


# Backup Management Routes

@router.get("/backups")
async def list_backups(request: Request):
    """List all available backup files."""
    if not check_auth(request):
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        backup_dir = Path("backups")
        backup_dir.mkdir(exist_ok=True)
        
        backups = []
        for backup_file in backup_dir.glob("*.json"):
            stats = backup_file.stat()
            backups.append({
                "name": backup_file.stem,
                "filename": backup_file.name,
                "date": datetime.fromtimestamp(stats.st_mtime).isoformat(),
                "size_bytes": stats.st_size,
                "size_mb": round(stats.st_size / (1024 * 1024), 2)
            })
        
        backups.sort(key=lambda x: x["date"], reverse=True)
        
        return {"backups": backups, "total": len(backups)}
    except Exception as e:
        logging.error(f"Error listing backups: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list backups: {str(e)}")


@router.post("/backups/create")
async def create_backup(request: Request):
    """Create a new backup of current settings."""
    if not check_auth(request):
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        backup_dir = Path("backups")
        backup_dir.mkdir(exist_ok=True)
        
        settings_file = Path("config/waf_settings.json")
        if not settings_file.exists():
            raise HTTPException(status_code=404, detail="Settings file not found")
        
        with open(settings_file, 'r') as f:
            settings = json.load(f)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"config_backup_{timestamp}.json"
        backup_path = backup_dir / backup_filename
        
        with open(backup_path, 'w') as f:
            json.dump(settings, f, indent=2)
        
        stats = backup_path.stat()
        
        return {
            "status": "success",
            "message": "Backup created successfully",
            "backup": {
                "name": backup_path.stem,
                "filename": backup_filename,
                "date": datetime.now().isoformat(),
                "size_mb": round(stats.st_size / (1024 * 1024), 2)
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error creating backup: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create backup: {str(e)}")


@router.get("/backups/download/{filename}")
async def download_backup(filename: str, request: Request):
    """Download a specific backup file."""
    if not check_auth(request):
        # For download, maybe redirect? But it's an API. Let's return 401.
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        backup_dir = Path("backups")
        backup_path = backup_dir / filename
        
        if not backup_path.exists() or not backup_path.is_file():
            raise HTTPException(status_code=404, detail="Backup file not found")
        
        # Security check: prevent path traversal
        if ".." in filename or "/" in filename or "\\" in filename:
            raise HTTPException(status_code=400, detail="Invalid filename")
        
        with open(backup_path, 'r') as f:
            content = f.read()
        
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error downloading backup: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to download backup: {str(e)}")


@router.delete("/backups/delete/{filename}")
async def delete_backup(filename: str, request: Request):
    """Delete a specific backup file."""
    if not check_auth(request):
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        backup_dir = Path("backups")
        backup_path = backup_dir / filename
        
        if not backup_path.exists() or not backup_path.is_file():
            raise HTTPException(status_code=404, detail="Backup file not found")
        
        # Security check: prevent path traversal
        if ".." in filename or "/" in filename or "\\" in filename:
            raise HTTPException(status_code=400, detail="Invalid filename")
        
        backup_path.unlink()
        
        return {
            "status": "success",
            "message": f"Backup '{filename}' deleted successfully"
        }
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error deleting backup: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete backup: {str(e)}")


@router.post("/rules/toggle")
async def toggle_security_rule(request: Request):
    """Toggle a specific security rule on/off."""
    if not check_auth(request):
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        body = await request.json()
        waf_engine = get_waf_engine(request)
        rule_name = body.get('rule_name')
        enabled = body.get('enabled')
        
        rule_mapping = {
            'sql_injection': 'sql_injection_protection',
            'xss': 'xss_protection',
            'path_traversal': 'path_traversal_protection',
            'rate_limit': 'rate_limit_enabled',
            'file_upload': 'file_upload_scanning',
            'ip_reputation': 'ip_reputation_enabled',
            'auto_ip_blocking': 'auto_ip_blocking'
        }
        
        if rule_name not in rule_mapping:
            return JSONResponse(
                status_code=400,
                content={"error": "Invalid rule name"}
            )
        
        setting_name = rule_mapping[rule_name]
        setattr(waf_engine.settings, setting_name, enabled)
        
        if rule_name == 'rate_limit':
            setattr(waf_engine.settings, 'ddos_protection', enabled)
        
        current_value = getattr(waf_engine.settings, setting_name)
        
        return {
            "success": True,
            "message": f"Rule {rule_name} {'enabled' if enabled else 'disabled'}",
            "current_value": current_value
        }
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": str(e)}
        )


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0",
        "waf_engine": "operational"
    }
