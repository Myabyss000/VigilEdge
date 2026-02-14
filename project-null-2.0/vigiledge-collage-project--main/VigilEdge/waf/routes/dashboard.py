"""
Dashboard Routes for VigilEdge WAF
Handles all page routes for the dashboard UI.
"""

import os
import logging
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .auth import check_auth

router = APIRouter(tags=["Dashboard"])

# Get directory paths
current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates_dir = os.path.join(current_dir, "templates")
templates = Jinja2Templates(directory=templates_dir)


def get_waf_engine():
    """Get WAF engine from app state - must be set during app initialization."""
    from app import waf_engine
    return waf_engine


@router.get("/", response_class=HTMLResponse)
async def root():
    """Redirect directly to admin dashboard."""
    return RedirectResponse(url="/admin/dashboard", status_code=302)


@router.get("/admin")
async def redirect_to_protected_admin():
    """Redirect /admin to the protected vulnerable app admin panel."""
    return RedirectResponse(url="/protected/admin", status_code=302)


@router.get("/admin/logout")
async def redirect_to_protected_logout():
    """Redirect logout to the protected vulnerable app logout."""
    return RedirectResponse(url="/protected/admin/logout", status_code=302)


@router.get("/dashboard", response_class=HTMLResponse)
async def customer_dashboard(request: Request):
    """Serve customer/user dashboard with limited features."""
    if not check_auth(request):
        return RedirectResponse(url="/login", status_code=302)
    try:
        waf_engine = get_waf_engine()
        metrics = await waf_engine.get_metrics()
        
        template_path = os.path.join(templates_dir, "customer_dashboard.html")
        with open(template_path, "r", encoding="utf-8") as f:
            template_content = f.read()
            
        # Replace placeholders with default data
        template_content = template_content.replace(
            "{{ username }}", "WAF User"
        ).replace(
            "{{ role }}", "User"
        ).replace(
            "{{ metrics.total_requests }}", str(metrics.get('total_requests', 0))
        ).replace(
            "{{ metrics.blocked_requests }}", str(metrics.get('blocked_requests', 0))
        ).replace(
            "{{ username[0].upper() if username else 'U' }}", "U"
        ).replace(
            "{{ username or 'User' }}", "User"
        ).replace(
            "{{ role.title() if role else 'Customer' }}", "User"
        ).replace(
            "{{ metrics.total_requests or 1247 }}", str(metrics.get('total_requests', 1247))
        ).replace(
            "{{ metrics.blocked_requests or 23 }}", str(metrics.get('blocked_requests', 23))
        )
        
        return HTMLResponse(content=template_content)
    except FileNotFoundError:
        return HTMLResponse("""
        <html>
        <body>
        <h1>Dashboard Error</h1>
        <p>Customer dashboard template not found.</p>
        <a href="/admin/dashboard">Go to Admin Dashboard</a>
        </body>
        </html>
        """, status_code=404)


@router.get("/admin/dashboard", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    """Serve the full admin dashboard with complete access."""
    if not check_auth(request):
        return RedirectResponse(url="/login", status_code=302)
    try:
        waf_engine = get_waf_engine()
        metrics = await waf_engine.get_metrics()
        blocked_ips = await waf_engine.get_blocked_ips()
        
        template_path = os.path.join(templates_dir, "enhanced_dashboard.html")
        with open(template_path, "r", encoding="utf-8") as f:
            template_content = f.read()
            
        template_content = template_content.replace(
            "{{TOTAL_REQUESTS}}", str(metrics.get('total_requests', 0))
        ).replace(
            "{{BLOCKED_REQUESTS}}", str(metrics.get('blocked_requests', 0))
        ).replace(
            "{{THREATS_DETECTED}}", str(metrics.get('threats_detected', 0))
        ).replace(
            "{{BLOCKED_IPS_COUNT}}", str(len(blocked_ips))
        )
        
        return HTMLResponse(content=template_content)
    except FileNotFoundError:
        return HTMLResponse("""
        <html>
        <body>
        <h1>Admin Dashboard Error</h1>
        <p>Enhanced dashboard template not found.</p>
        </body>
        </html>
        """, status_code=404)


@router.get("/enhanced", response_class=HTMLResponse)
async def enhanced_dashboard(request: Request):
    """Serve the enhanced cyber-themed dashboard."""
    if not check_auth(request):
        return RedirectResponse(url="/login", status_code=302)
    try:
        template_path = os.path.join(templates_dir, "enhanced_dashboard.html")
        with open(template_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return HTMLResponse("""
        <html>
        <body>
        <h1>Enhanced Dashboard Not Found</h1>
        <p>The enhanced dashboard template is not available.</p>
        <a href="/classic">Go to Classic Dashboard</a>
        </body>
        </html>
        """, status_code=404)


@router.get("/classic", response_class=HTMLResponse)
async def classic_dashboard(request: Request):
    """Serve the classic dashboard - loads from template file."""
    if not check_auth(request):
        return RedirectResponse(url="/login", status_code=302)
    try:
        template_path = os.path.join(templates_dir, "dashboard_classic.html")
        with open(template_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        # Fallback if template doesn't exist
        return HTMLResponse("""
        <html>
        <body style="background: #0a0e1a; color: white; font-family: Arial; padding: 2rem;">
        <h1 style="color: #00d4ff;">VigilEdge WAF - Classic Dashboard</h1>
        <p>Classic dashboard template not found. Please use the enhanced dashboard.</p>
        <a href="/enhanced" style="color: #00ffa6;">Go to Enhanced Dashboard</a>
        </body>
        </html>
        """, status_code=200)


@router.get("/security-rules", response_class=HTMLResponse)
async def security_rules(request: Request):
    """Serve the security rules page with cache-busting."""
    if not check_auth(request):
        return RedirectResponse(url="/login", status_code=302)
    try:
        template_path = os.path.join(templates_dir, "security_rules.html")
        with open(template_path, "r", encoding="utf-8") as f:
            html_content = f.read()
            cache_buster = '<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate"><meta http-equiv="Pragma" content="no-cache"><meta http-equiv="Expires" content="0">'
            html_content = html_content.replace('<head>', f'<head>{cache_buster}')
            return html_content
    except FileNotFoundError:
        return HTMLResponse("""
        <html>
        <body>
        <h1>Security Rules Page Not Found</h1>
        <p>The security rules template is not available.</p>
        <a href="/">Go to Dashboard</a>
        </body>
        </html>
        """, status_code=404)


@router.get("/threat-detection", response_class=HTMLResponse)
async def threat_detection(request: Request):
    """Serve the threat detection page."""
    if not check_auth(request):
        return RedirectResponse(url="/login", status_code=302)
    try:
        template_data = {
            "request": request,
            "page_title": "Threat Detection",
            "waf_status": "active"
        }
        return templates.TemplateResponse("threat_detection.html", template_data)
    except Exception as e:
        logging.error(f"Error loading threat detection page: {e}")
        return HTMLResponse("""
        <html>
        <body style="background: #0a0e1a; color: white; font-family: Arial; padding: 2rem;">
        <h1 style="color: #00d4ff;">Threat Detection</h1>
        <p>The threat detection page is under maintenance.</p>
        <a href="/" style="color: #00ffa6;">← Go to Dashboard</a>
        </body>
        </html>
        """, status_code=200)


@router.get("/analytics", response_class=HTMLResponse)
async def analytics(request: Request):
    """Serve the analytics page."""
    if not check_auth(request):
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("analytics.html", {"request": request})


@router.get("/visualization-demo", response_class=HTMLResponse)
async def visualization_demo(request: Request):
    """Serve the attack visualization demo page."""
    if not check_auth(request):
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("visualization_demo.html", {"request": request})


@router.get("/ai-analysis", response_class=HTMLResponse)
async def ai_analysis(request: Request):
    """Serve the AI analysis page."""
    if not check_auth(request):
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("ai_analysis.html", {"request": request})


@router.get("/network-monitor", response_class=HTMLResponse)
async def network_monitor(request: Request):
    """Serve the enhanced network monitor page."""
    if not check_auth(request):
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("network_monitor.html", {"request": request})


@router.get("/blocked-ips", response_class=HTMLResponse)
async def blocked_ips_page(request: Request):
    """Serve the blocked IPs page with real data."""
    if not check_auth(request):
        return RedirectResponse(url="/login", status_code=302)
    try:
        waf_engine = get_waf_engine()
        blocked_ips_data = await waf_engine.get_blocked_ips()
        
        stats = {
            'total_blocked': len(blocked_ips_data),
            'blocked_today': sum(1 for ip in blocked_ips_data if ip.get('is_today', False)),
            'automatic_blocks': sum(1 for ip in blocked_ips_data if ip.get('reason_type') in ['malicious', 'suspicious', 'bot']),
            'manual_blocks': sum(1 for ip in blocked_ips_data if ip.get('reason_type') == 'manual')
        }
        
        template_data = {
            "request": request,
            "blocked_ips": blocked_ips_data,
            "stats": stats,
            "page_title": "Blocked IPs",
            "waf_status": "active"
        }
        
        return templates.TemplateResponse("blocked_ips.html", template_data)
        
    except Exception as e:
        logging.error(f"Error loading blocked IPs page: {e}")
        template_data = {
            "request": request,
            "blocked_ips": [],
            "stats": {'total_blocked': 0, 'blocked_today': 0, 'automatic_blocks': 0, 'manual_blocks': 0},
            "page_title": "Blocked IPs",
            "waf_status": "active"
        }
        return templates.TemplateResponse("blocked_ips.html", template_data)


@router.get("/event-logs", response_class=HTMLResponse)
async def event_logs_page(request: Request):
    """Serve the event logs page with real data."""
    if not check_auth(request):
        return RedirectResponse(url="/login", status_code=302)
    try:
        waf_engine = get_waf_engine()
        recent_events = await waf_engine.get_recent_events(limit=20)
        
        template_data = {
            "request": request,
            "events": recent_events,
            "total_events": len(recent_events),
            "page_title": "Event Logs",
            "waf_status": "active"
        }
        
        return templates.TemplateResponse("event_logs.html", template_data)
        
    except Exception as e:
        logging.error(f"Error loading event logs page: {e}")
        template_data = {
            "request": request,
            "events": [],
            "page_title": "Event Logs",
            "waf_status": "active"
        }
        return templates.TemplateResponse("event_logs.html", template_data)


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Serve the settings page."""
    if not check_auth(request):
        return RedirectResponse(url="/login", status_code=302)
    try:
        template_data = {
            "request": request,
            "page_title": "Settings", 
            "waf_status": "active"
        }
        return templates.TemplateResponse("settings.html", template_data)
    except Exception as e:
        logging.error(f"Error loading settings page: {e}")
        return HTMLResponse("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Settings - VigilEdge WAF</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    background: linear-gradient(135deg, #0a0e1a 0%, #1a1f2e 100%);
                    color: white;
                    margin: 0;
                    padding: 2rem;
                }
                .container { max-width: 1200px; margin: 0 auto; }
                h1 { color: #00d4ff; margin-bottom: 2rem; }
                .back-link { color: #00ffa6; text-decoration: none; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>WAF Settings</h1>
                <p>Settings page is loading...</p>
                <a href="/" class="back-link">← Back to Dashboard</a>
            </div>
        </body>
        </html>
        """)
