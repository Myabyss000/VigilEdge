"""
Authentication Routes
Handles login/logout functionality for the WAF dashboard.
"""

from urllib.parse import parse_qs
from typing import Any, Dict

from fastapi import APIRouter, Request, Response, Form, Depends, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import APIKeyCookie
import os
import pyotp
import json
import base64
from io import BytesIO
import qrcode
from pathlib import Path

from vigiledge.config import get_settings

router = APIRouter(tags=["Authentication"])

# Setup templates
current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates_dir = os.path.join(current_dir, "templates")
templates = Jinja2Templates(directory=templates_dir)

settings = get_settings()

COOKIE_NAME = "vigiledge_auth"
SETTINGS_PATH = Path("config/waf_settings.json")


def load_settings_file() -> Dict[str, Any]:
    """Load persisted WAF settings from disk."""
    if SETTINGS_PATH.exists():
        with open(SETTINGS_PATH, "r") as settings_file:
            return json.load(settings_file)
    return {}


def save_settings_file(data: Dict[str, Any]) -> None:
    """Persist WAF settings to disk."""
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(SETTINGS_PATH, "w") as settings_file:
        json.dump(data, settings_file, indent=2)


def get_auth_config() -> Dict[str, Any]:
    """Return the authentication section from persisted settings."""
    return load_settings_file().get("authentication", {})


def is_2fa_configured() -> bool:
    """Return whether a TOTP secret has already been enrolled."""
    return bool(get_auth_config().get("totp_secret"))


def get_effective_admin_credentials(request: Request) -> tuple[str, str]:
    """Resolve the current admin username/password from app state or persisted settings."""
    app_settings = request.app.state.settings
    auth_config = get_auth_config()
    admin_username = auth_config.get("admin_username") or app_settings.admin_username
    admin_password = auth_config.get("admin_password") or app_settings.admin_password
    return admin_username, admin_password


def qr_b64_from_secret(secret: str) -> str:
    """Generate a base64-encoded QR image for a TOTP secret."""
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name="Admin",
        issuer_name="VigilEdge WAF",
    )
    img = qrcode.make(uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode("utf-8")

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Serve the login page."""
    # If already logged in, redirect to dashboard
    if request.cookies.get(COOKIE_NAME):
        return RedirectResponse(url="/admin/dashboard", status_code=302)

    query_params = parse_qs(request.url.query)
    message = None
    if query_params.get("msg") == ["password_reset"]:
        message = "Password updated successfully. You can now sign in with your new password."
    elif query_params.get("msg") == ["2fa_enabled"]:
        message = "Two-factor authentication is enabled. You can now use password recovery with your authenticator code."
    elif query_params.get("msg") == ["2fa_bootstrap_required"]:
        message = "Sign in first to manage 2FA. If 2FA has not been configured yet, use the setup link below."

    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "message": message,
            "show_setup_2fa": not is_2fa_configured(),
        },
    )


@router.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...)
):
    """Handle login form submission."""
    app_settings = request.app.state.settings
    effective_username, effective_password = get_effective_admin_credentials(request)
    auth_success = username == effective_username and password == effective_password

    if auth_success:
        # Self-repair: keep app state aligned with persisted settings.
        app_settings.admin_username = effective_username
        app_settings.admin_password = effective_password

    if auth_success:
        # Create response with redirect
        response = RedirectResponse(url="/admin/dashboard", status_code=303)
        
        # Set secure cookie
        response.set_cookie(
            key=COOKIE_NAME,
            value="authenticated", # In a real app, use a JWT or signed session token
            httponly=True,
            secure=app_settings.environment == "production", # Only secure in prod (or if using https locally)
            max_age=86400, # 24 hours persistence
            samesite="lax"
        )
        return response
    
    # Login failed
    return templates.TemplateResponse(
        "login.html", 
        {"request": request, "error": "Invalid Operator ID or Access Key"}, 
        status_code=401
    )


@router.get("/logout")
async def logout(response: Response):
    """Handle logout."""
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(COOKIE_NAME)
    return response



# --- 2FA Password Reset Routes ---

@router.get("/auth/reset-password", response_class=HTMLResponse)
async def reset_password_page(request: Request):
    """Serve the password reset page."""
    setup_required = not is_2fa_configured()

    return templates.TemplateResponse(
        "reset_password.html",
        {
            "request": request,
            "setup_required": setup_required,
        },
    )

@router.post("/auth/reset-password", response_class=HTMLResponse)
async def reset_password_action(
    request: Request,
    totp_code: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...)
):
    """Handle password reset with TOTP verification."""
    
    # 1. Validation
    if new_password != confirm_password:
        return templates.TemplateResponse(
            "reset_password.html",
            {"request": request, "error": "Passwords do not match"}
        )

    # 2. Verify TOTP
    try:
        if not SETTINGS_PATH.exists():
             return templates.TemplateResponse(
                "reset_password.html",
                {"request": request, "error": "System not initialized (Settings file missing)"}
            )
            
        file_settings = load_settings_file()
            
        auth_config = file_settings.get("authentication", {})
        secret = auth_config.get("totp_secret")
        
        if not secret:
            return templates.TemplateResponse(
                "reset_password.html",
                {
                    "request": request,
                    "error": "2FA is not set up on this server yet. Sign in with the current admin password and open Setup 2FA first, or run the local setup_2fa.py bootstrap script.",
                    "setup_required": True,
                }
            )
            
        totp = pyotp.TOTP(secret)
        if not totp.verify(totp_code.replace(" ", "")): # Handle spaces if user types them
            return templates.TemplateResponse(
                "reset_password.html",
                {"request": request, "error": "Invalid Authentication Code", "setup_required": False}
            )
            
        # 3. Success - Update Password
        if "authentication" not in file_settings:
            file_settings["authentication"] = {}

        file_settings["authentication"]["admin_username"] = request.app.state.settings.admin_username
        file_settings["authentication"]["admin_password"] = new_password
        
        save_settings_file(file_settings)
            
        # Update memory state if available
        if hasattr(request.app.state, "settings"):
            request.app.state.settings.admin_password = new_password
            
        return RedirectResponse(url="/login?msg=password_reset", status_code=303)
        
    except Exception as e:
        print(f"Reset Error: {e}")
        return templates.TemplateResponse(
            "reset_password.html",
            {"request": request, "error": f"System Error: {str(e)}", "setup_required": False}
        )

# --- 2FA Setup Routes (New) ---

@router.get("/auth/setup-2fa", response_class=HTMLResponse)
async def setup_2fa_page(request: Request):
    """Serve the 2FA setup page with a new QR code."""
    authenticated = check_auth(request)
    already_configured = is_2fa_configured()

    if not authenticated and already_configured:
        return RedirectResponse(url="/login?msg=2fa_bootstrap_required", status_code=302)
        
    # Generate new secret
    secret = pyotp.random_base32()
    
    qr_b64 = qr_b64_from_secret(secret)
    
    return templates.TemplateResponse("setup_2fa.html", {
        "request": request, 
        "secret": secret,
        "qr_b64": qr_b64,
        "bootstrap_mode": not authenticated,
        "already_configured": already_configured,
    })

@router.post("/auth/verify-2fa", response_class=HTMLResponse)
async def verify_2fa_setup(
    request: Request,
    secret: str = Form(...),
    code: str = Form(...),
    current_password: str = Form(default=""),
):
    """Verify and save the new 2FA secret."""
    authenticated = check_auth(request)
    already_configured = is_2fa_configured()

    if not authenticated and already_configured:
        return RedirectResponse(url="/login", status_code=302)

    if not authenticated:
        _, admin_password = get_effective_admin_credentials(request)
        if current_password != admin_password:
            return templates.TemplateResponse(
                "setup_2fa.html",
                {
                    "request": request,
                    "secret": secret,
                    "qr_b64": qr_b64_from_secret(secret),
                    "bootstrap_mode": True,
                    "already_configured": False,
                    "error": "Current admin password is required to activate 2FA.",
                },
                status_code=401,
            )
        
    totp = pyotp.TOTP(secret)
    normalized_code = code.replace(" ", "")
    if totp.verify(normalized_code, valid_window=1):
        # Valid! Save to settings
        try:
            settings_data = load_settings_file()
                
            if "authentication" not in settings_data:
                settings_data["authentication"] = {}

            settings_data["authentication"]["admin_username"] = request.app.state.settings.admin_username
            settings_data["authentication"]["totp_secret"] = secret
            settings_data["authentication"]["2fa_enabled"] = True
            
            save_settings_file(settings_data)
                
            if authenticated:
                return RedirectResponse(url="/admin/dashboard?msg=2fa_enabled", status_code=303)
            return RedirectResponse(url="/login?msg=2fa_enabled", status_code=303)
            
        except Exception as e:
            return HTMLResponse(f"Error saving settings: {e}", status_code=500)
    else:
        return templates.TemplateResponse(
            "setup_2fa.html",
            {
                "request": request,
                "secret": secret,
                "qr_b64": qr_b64_from_secret(secret),
                "bootstrap_mode": not authenticated,
                "already_configured": already_configured,
                "error": "Invalid authentication code. Check the current 6-digit code and try again.",
            },
            status_code=400,
        )

# --- End 2FA Routes ---


# --- Dependency for protecting routes ---

async def get_current_user(request: Request):
    """
    Dependency to check if user is authenticated.
    Redirects to /login if not authenticated.
    """
    auth_cookie = request.cookies.get(COOKIE_NAME)
    if not auth_cookie:
        # Raising HTTPException(401) is API friendly, but for browser interaction
        # we often want a redirect. However, dependencies usually raise exceptions.
        # We can handle this by letting the route handle it or using a middleware approach.
        # Ideally, valid auth returns the user, invalid raises.
        # For simplicity in this structure, we'll return None if not auth.
        # Using check_auth locally in routes is safer for redirects.
        return None
    return auth_cookie


def check_auth(request: Request):
    """
    Helper to check auth and raise exception if needed.
    Used for direct checks in code where we want to redirect manually.
    """
    if not request.cookies.get(COOKIE_NAME):
        return False
    return True
