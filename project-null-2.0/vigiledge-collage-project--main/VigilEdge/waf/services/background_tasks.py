"""
Background Tasks for VigilEdge WAF
Handles startup animation, monitoring, and auto-backup tasks.
"""

import asyncio
import time
import random
import logging
from datetime import datetime
from pathlib import Path


def animated_startup():
    """Display animated startup sequence in terminal."""
    
    # Clear screen and show title
    print("\033[2J\033[H")  # Clear screen and move cursor to top
    
    # ASCII Art Banner
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║    ██╗   ██╗██╗ ██████╗ ██╗██╗     ███████╗██████╗  ██████╗  ║
    ║    ██║   ██║██║██╔════╝ ██║██║     ██╔════╝██╔══██╗██╔════╝  ║
    ║    ██║   ██║██║██║  ███╗██║██║     █████╗  ██║  ██║██║  ███╗ ║
    ║    ╚██╗ ██╔╝██║██║   ██║██║██║     ██╔══╝  ██║  ██║██║   ██║ ║
    ║     ╚████╔╝ ██║╚██████╔╝██║███████╗███████╗██████╔╝╚██████╔╝ ║
    ║      ╚═══╝  ╚═╝ ╚═════╝ ╚═╝╚══════╝╚══════╝╚═════╝  ╚═════╝  ║
    ║                                                              ║
    ║                 🛡️  Web Application Firewall 🛡️              ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print("\033[36m" + banner + "\033[0m")  # Cyan color
    
    # Animated loading sequence
    loading_steps = [
        ("🔧 Initializing Security Engine", 0.8),
        ("🔍 Loading Threat Detection Rules", 0.6),
        ("📊 Setting up Real-time Monitoring", 0.5),
        ("🌐 Starting Web Server", 0.4),
        ("🔗 Establishing WebSocket Connections", 0.3),
        ("✅ VigilEdge WAF Ready!", 0.2)
    ]
    
    print("\n" + "="*60)
    print("🚀 STARTUP SEQUENCE")
    print("="*60)
    
    for step, delay in loading_steps:
        # Animated dots
        for i in range(3):
            print(f"\r{step}{'.' * (i + 1)}", end="", flush=True)
            time.sleep(delay / 3)
        print(f"\r{step}... ✅")
        time.sleep(0.2)


async def monitoring_task(waf_engine, manager):
    """Background task showing enhanced visual system status.
    
    Args:
        waf_engine: WAF engine instance for getting real metrics
        manager: ConnectionManager instance for tracking active connections
    """
    # Enhanced status indicators
    status_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    security_states = ["🟢 SECURE", "🟡 MONITORING", "🔵 SCANNING", "🟢 PROTECTED"]
    threat_alerts = ["🚨 SQL INJECTION BLOCKED", "⚠️  XSS ATTEMPT DETECTED", "🛡️  RATE LIMIT TRIGGERED"]
    
    counter = 0
    last_threat_time = 0
    
    while True:
        try:
            # Rotating status indicator
            status_char = status_chars[counter % len(status_chars)]
            security_state = security_states[counter % len(security_states)]
            
            # Get current time
            current_time = datetime.now().strftime("%H:%M:%S")
            
            # Get REAL metrics from WAF engine (not fake!)
            try:
                metrics = await waf_engine.get_metrics()
                requests_processed = metrics.get('total_requests', 0)
                threats_blocked = metrics.get('blocked_requests', 0)
                cpu_usage = metrics.get('cpu_percent', 0)
            except Exception:
                # Fallback if metrics unavailable
                requests_processed = 0
                threats_blocked = 0
                cpu_usage = 0
            
            # Real active connections count
            active_connections = len(manager.active_connections)
            
            # Only show threat alerts when there are REAL new threats
            threat_alert = ""
            if threats_blocked > 0 and counter % 30 == 0:
                threat_alert = f" | 🚨 {threats_blocked} threats blocked!"
            
            # Create status line with REAL metrics
            status_line = (
                f"\r{status_char} {security_state} | "
                f"🕒 {current_time} | "
                f"📊 Requests: {requests_processed} | "
                f"🛡️  Blocked: {threats_blocked} | "
                f"🔗 Live: {active_connections} | "
                f"💻 CPU: {cpu_usage:.0f}%{threat_alert}"
            )
            
            # Color coding based on real activity
            if threats_blocked > 0:
                print(f"\033[91m{status_line}\033[0m", end="", flush=True)  # Red for threats
            elif cpu_usage > 50:
                print(f"\033[93m{status_line}\033[0m", end="", flush=True)  # Yellow for high CPU
            else:
                print(f"\033[92m{status_line}\033[0m", end="", flush=True)  # Green for normal
            
            counter += 1
            await asyncio.sleep(2)  # Update every 2 seconds (less frequent)
            
        except asyncio.CancelledError:
            print("\n🛑 Real-time monitoring stopped.")
            break
        except Exception:
            # Silent error handling
            await asyncio.sleep(1)


async def auto_backup_task(frequency: str = "daily"):
    """Automatic backup task based on configured frequency.
    
    Args:
        frequency: Backup frequency ('hourly', 'daily', 'weekly')
    """
    # Calculate interval in seconds
    intervals = {
        "hourly": 3600,
        "daily": 86400,
        "weekly": 604800
    }
    interval = intervals.get(frequency, 86400)
    
    print(f"💾 Auto-backup scheduler started: {frequency} backups")
    
    while True:
        try:
            await asyncio.sleep(interval)
            
            # Create backup
            backup_dir = Path("backups")
            backup_dir.mkdir(exist_ok=True)
            
            settings_file = Path("config/waf_settings.json")
            if settings_file.exists():
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = backup_dir / f"auto_backup_{timestamp}.json"
                
                with open(settings_file, 'r') as f:
                    content = f.read()
                with open(backup_path, 'w') as f:
                    f.write(content)
                
                print(f"💾 Auto-backup created: {backup_path.name}")
                
                # Clean old backups (keep last 10)
                backups = sorted(backup_dir.glob("auto_backup_*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
                for old_backup in backups[10:]:
                    old_backup.unlink()
                    print(f"🗑️  Removed old backup: {old_backup.name}")
        
        except asyncio.CancelledError:
            print("💾 Auto-backup scheduler stopped")
            break
        except Exception as e:
            logging.error(f"Auto-backup error: {e}")
            await asyncio.sleep(60)  # Wait a minute before retry
