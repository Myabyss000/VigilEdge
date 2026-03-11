"""
Authentication Routes
Handles login/logout functionality for the WAF dashboard.
"""

from urllib.parse import parse_qs
from typing import Any, Dict
import secrets
import hashlib
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Request, Response, Form, Depends, status, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import APIKeyCookie, HTTPBearer, HTTPAuthorizationCredentials
import os
import pyotp
import json
import base64
from io import BytesIO
import qrcode
from pathlib import Path
from jose import JWTError, jwt

from vigiledge.config import get_settings

router = APIRouter(tags=["Authentication"])

# Setup templates
current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates_dir = os.path.join(current_dir, "templates")
templates = Jinja2Templates(directory=templates_dir)

settings = get_settings()

COOKIE_NAME = "vigiledge_auth"
SETTINGS_PATH = Path("config/waf_settings.json")
bearer_scheme = HTTPBearer(auto_error=False)
SESSION_TOKEN_TYPE = "admin_session"
CSRF_COOKIE_NAME = "vigiledge_csrf"


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


def is_auth_initialized(app_settings) -> bool:
    """Return whether the WAF admin account has been explicitly initialized."""
    auth_config = get_auth_config()
    if auth_config.get("bootstrap_completed"):
        return True

    admin_username = auth_config.get("admin_username") or app_settings.admin_username
    admin_password = auth_config.get("admin_password") or app_settings.admin_password
    return not (admin_username == "admin" and admin_password == "admin")


def is_bootstrap_token_valid(request: Request, submitted_token: str) -> bool:
    """Validate the configured bootstrap token used for first-run admin setup."""
    configured_token = getattr(request.app.state.settings, "bootstrap_admin_token", "") or ""
    if not configured_token or not submitted_token:
        return False
    return secrets.compare_digest(configured_token.strip(), submitted_token.strip())


def issue_csrf_token(response: Response) -> str:
    """Issue a double-submit CSRF token cookie for HTML form posts."""
    csrf_token = secrets.token_urlsafe(32)
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        secure=settings.environment == "production",
        samesite="lax",
        max_age=3600,
        path="/",
    )
    return csrf_token


def validate_csrf_token(request: Request, submitted_token: str) -> bool:
    """Validate the double-submit CSRF token for form-based admin actions."""
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME, "")
    if not cookie_token or not submitted_token:
        return False
    return secrets.compare_digest(cookie_token, submitted_token)


def template_response_with_csrf(template_name: str, context: Dict[str, Any], status_code: int = 200) -> Response:
    """Render a template response and include a CSRF token in both context and cookie."""
    csrf_token = secrets.token_urlsafe(32)
    enriched_context = dict(context)
    enriched_context["csrf_token"] = csrf_token
    response = templates.TemplateResponse(template_name, enriched_context, status_code=status_code)
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        secure=settings.environment == "production",
        samesite="lax",
        max_age=3600,
        path="/",
    )
    return response


def is_2fa_configured() -> bool:
    """Return whether a TOTP secret has already been enrolled."""
    return bool(get_auth_config().get("totp_secret"))


def get_effective_admin_credentials_from_settings(app_settings) -> tuple[str, str]:
    """Resolve the current admin username/password from app state or persisted settings."""
    auth_config = get_auth_config()
    admin_username = auth_config.get("admin_username") or app_settings.admin_username
    admin_password = auth_config.get("admin_password") or app_settings.admin_password
    return admin_username, admin_password


def get_effective_admin_credentials(request: Request) -> tuple[str, str]:
    """Resolve the current admin username/password from request state or persisted settings."""
    return get_effective_admin_credentials_from_settings(request.app.state.settings)


def build_auth_fingerprint(username: str, password: str, secret_key: str) -> str:
    """Create a deterministic fingerprint that invalidates old tokens on password change."""
    material = f"{username}:{password}:{secret_key}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def create_admin_session_token(app_settings, username: str, password: str) -> str:
    """Issue a signed JWT for the authenticated WAF admin session."""
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=app_settings.access_token_expire_minutes)
    payload = {
        "sub": username,
        "token_type": SESSION_TOKEN_TYPE,
        "iat": now,
        "exp": expires_at,
        "auth_fingerprint": build_auth_fingerprint(username, password, app_settings.secret_key),
    }
    return jwt.encode(payload, app_settings.secret_key, algorithm=app_settings.algorithm)


def validate_admin_session_token(token: str, app_settings) -> Dict[str, Any] | None:
    """Validate the signed WAF admin session token and return its claims when valid."""
    if not token:
        return None

    try:
        payload = jwt.decode(token, app_settings.secret_key, algorithms=[app_settings.algorithm])
    except JWTError:
        return None

    username, password = get_effective_admin_credentials_from_settings(app_settings)
    if payload.get("token_type") != SESSION_TOKEN_TYPE:
        return None
    if payload.get("sub") != username:
        return None

    expected_fingerprint = build_auth_fingerprint(username, password, app_settings.secret_key)
    if not secrets.compare_digest(payload.get("auth_fingerprint", ""), expected_fingerprint):
        return None

    return payload


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
    if not is_auth_initialized(request.app.state.settings):
        return RedirectResponse(url="/bootstrap", status_code=303)

    # If already logged in, redirect to dashboard
    if check_auth(request):
        return RedirectResponse(url="/admin/dashboard", status_code=302)

    query_params = parse_qs(request.url.query)
    message = None
    if query_params.get("msg") == ["password_reset"]:
        message = "Password updated successfully. You can now sign in with your new password."
    elif query_params.get("msg") == ["2fa_enabled"]:
        message = "Two-factor authentication is enabled. You can now use password recovery with your authenticator code."
    elif query_params.get("msg") == ["2fa_bootstrap_required"]:
        message = "Sign in first to manage 2FA. If 2FA has not been configured yet, use the setup link below."

    return template_response_with_csrf(
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
    password: str = Form(...),
    csrf_token: str = Form(""),
):
    """Handle login form submission."""
    if not is_auth_initialized(request.app.state.settings):
        return RedirectResponse(url="/bootstrap", status_code=303)

    if not validate_csrf_token(request, csrf_token):
        return template_response_with_csrf(
            "login.html",
            {
                "request": request,
                "error": "Security token expired. Please refresh and try again.",
                "show_setup_2fa": not is_2fa_configured(),
            },
            status_code=400,
        )

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
        session_token = create_admin_session_token(app_settings, effective_username, effective_password)
        
        # Set signed JWT cookie
        response.set_cookie(
            key=COOKIE_NAME,
            value=session_token,
            httponly=True,
            secure=app_settings.environment == "production",
            max_age=app_settings.access_token_expire_minutes * 60,
            samesite="lax",
            path="/",
        )
        response.delete_cookie(CSRF_COOKIE_NAME, path="/")
        return response
    
    # Login failed
    return template_response_with_csrf(
        "login.html", 
        {
            "request": request,
            "error": "Invalid Operator ID or Access Key",
            "show_setup_2fa": not is_2fa_configured(),
        }, 
        status_code=401
    )


@router.get("/bootstrap", response_class=HTMLResponse)
async def bootstrap_page(request: Request):
    """Serve first-run admin bootstrap when default credentials have not been replaced."""
    if is_auth_initialized(request.app.state.settings):
        return RedirectResponse(url="/login", status_code=303)

    return template_response_with_csrf(
        "bootstrap.html",
        {
            "request": request,
            "error": None,
            "bootstrap_token_required": bool(request.app.state.settings.bootstrap_admin_token),
        },
    )


@router.post("/bootstrap", response_class=HTMLResponse)
async def bootstrap_admin(
    request: Request,
    admin_username: str = Form(...),
    admin_password: str = Form(...),
    confirm_password: str = Form(...),
    bootstrap_token: str = Form(""),
    csrf_token: str = Form(""),
):
    """Initialize the first WAF admin account and mark bootstrap complete."""
    if is_auth_initialized(request.app.state.settings):
        return RedirectResponse(url="/login", status_code=303)

    if not validate_csrf_token(request, csrf_token):
        return template_response_with_csrf(
            "bootstrap.html",
            {
                "request": request,
                "error": "Security token expired. Please refresh and try again.",
                "bootstrap_token_required": bool(request.app.state.settings.bootstrap_admin_token),
            },
            status_code=400,
        )

    if request.app.state.settings.bootstrap_admin_token and not is_bootstrap_token_valid(request, bootstrap_token):
        return template_response_with_csrf(
            "bootstrap.html",
            {
                "request": request,
                "error": "Invalid bootstrap token.",
                "bootstrap_token_required": True,
            },
            status_code=403,
        )

    normalized_username = (admin_username or "").strip()
    if len(normalized_username) < 3:
        return template_response_with_csrf(
            "bootstrap.html",
            {
                "request": request,
                "error": "Admin username must be at least 3 characters.",
                "bootstrap_token_required": bool(request.app.state.settings.bootstrap_admin_token),
            },
            status_code=400,
        )

    if len(admin_password) < 12:
        return template_response_with_csrf(
            "bootstrap.html",
            {
                "request": request,
                "error": "Admin password must be at least 12 characters.",
                "bootstrap_token_required": bool(request.app.state.settings.bootstrap_admin_token),
            },
            status_code=400,
        )

    if admin_password != confirm_password:
        return template_response_with_csrf(
            "bootstrap.html",
            {
                "request": request,
                "error": "Passwords do not match.",
                "bootstrap_token_required": bool(request.app.state.settings.bootstrap_admin_token),
            },
            status_code=400,
        )

    settings_data = load_settings_file()
    auth_config = settings_data.setdefault("authentication", {})
    auth_config["admin_username"] = normalized_username
    auth_config["admin_password"] = admin_password
    auth_config["bootstrap_completed"] = True
    save_settings_file(settings_data)

    request.app.state.settings.admin_username = normalized_username
    request.app.state.settings.admin_password = admin_password

    redirect_response = RedirectResponse(url="/admin/dashboard", status_code=303)
    session_token = create_admin_session_token(request.app.state.settings, normalized_username, admin_password)
    redirect_response.set_cookie(
        key=COOKIE_NAME,
        value=session_token,
        httponly=True,
        secure=request.app.state.settings.environment == "production",
        max_age=request.app.state.settings.access_token_expire_minutes * 60,
        samesite="lax",
        path="/",
    )
    redirect_response.delete_cookie(CSRF_COOKIE_NAME, path="/")
    return redirect_response


@router.get("/logout")
async def logout(response: Response):
    """Handle logout."""
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(COOKIE_NAME)
    response.delete_cookie(CSRF_COOKIE_NAME, path="/")
    return response



# --- 2FA Password Reset Routes ---

@router.get("/auth/reset-password", response_class=HTMLResponse)
async def reset_password_page(request: Request):
    """Serve the password reset page."""
    setup_required = not is_2fa_configured()

    return template_response_with_csrf(
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
    confirm_password: str = Form(...),
    csrf_token: str = Form(""),
):
    """Handle password reset with TOTP verification."""

    if not validate_csrf_token(request, csrf_token):
        return template_response_with_csrf(
            "reset_password.html",
            {
                "request": request,
                "error": "Security token expired. Please refresh and try again.",
                "setup_required": not is_2fa_configured(),
            },
            status_code=400,
        )
    
    # 1. Validation
    if new_password != confirm_password:
        return template_response_with_csrf(
            "reset_password.html",
            {"request": request, "error": "Passwords do not match", "setup_required": not is_2fa_configured()}
        )

    # 2. Verify TOTP
    try:
        if not SETTINGS_PATH.exists():
                  return template_response_with_csrf(
                "reset_password.html",
                     {"request": request, "error": "System not initialized (Settings file missing)", "setup_required": not is_2fa_configured()}
            )
            
        file_settings = load_settings_file()
            
        auth_config = file_settings.get("authentication", {})
        secret = auth_config.get("totp_secret")
        
        if not secret:
            return template_response_with_csrf(
                "reset_password.html",
                {
                    "request": request,
                    "error": "2FA is not set up on this server yet. Sign in with the current admin password and open Setup 2FA first, or run the local setup_2fa.py bootstrap script.",
                    "setup_required": True,
                }
            )
            
        totp = pyotp.TOTP(secret)
        if not totp.verify(totp_code.replace(" ", "")): # Handle spaces if user types them
            return template_response_with_csrf(
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
            
        redirect_response = RedirectResponse(url="/login?msg=password_reset", status_code=303)
        redirect_response.delete_cookie(CSRF_COOKIE_NAME, path="/")
        return redirect_response
        
    except Exception as e:
        print(f"Reset Error: {e}")
        return template_response_with_csrf(
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
    
    return template_response_with_csrf("setup_2fa.html", {
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
    csrf_token: str = Form(""),
):
    """Verify and save the new 2FA secret."""
    authenticated = check_auth(request)
    already_configured = is_2fa_configured()

    if not validate_csrf_token(request, csrf_token):
        return template_response_with_csrf(
            "setup_2fa.html",
            {
                "request": request,
                "secret": secret,
                "qr_b64": qr_b64_from_secret(secret),
                "bootstrap_mode": not authenticated,
                "already_configured": already_configured,
                "error": "Security token expired. Please refresh and try again.",
            },
            status_code=400,
        )

    if not authenticated and already_configured:
        return RedirectResponse(url="/login", status_code=302)

    if not authenticated:
        _, admin_password = get_effective_admin_credentials(request)
        if current_password != admin_password:
            return template_response_with_csrf(
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
                redirect_response = RedirectResponse(url="/admin/dashboard?msg=2fa_enabled", status_code=303)
                redirect_response.delete_cookie(CSRF_COOKIE_NAME, path="/")
                return redirect_response
            redirect_response = RedirectResponse(url="/login?msg=2fa_enabled", status_code=303)
            redirect_response.delete_cookie(CSRF_COOKIE_NAME, path="/")
            return redirect_response
            
        except Exception as e:
            return HTMLResponse(f"Error saving settings: {e}", status_code=500)
    else:
        return template_response_with_csrf(
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
        return None
    return validate_admin_session_token(auth_cookie, request.app.state.settings)


def check_auth(request: Request):
    """
    Helper to check auth and raise exception if needed.
    Used for direct checks in code where we want to redirect manually.
    """
    auth_cookie = request.cookies.get(COOKIE_NAME)
    if not auth_cookie:
        return False
    return validate_admin_session_token(auth_cookie, request.app.state.settings) is not None


def get_control_plane_tokens_from_settings(settings_obj) -> list[str]:
    """Return configured service tokens for non-browser control-plane clients."""
    raw_tokens = getattr(settings_obj, "control_plane_api_tokens", "") or ""
    return [token.strip() for token in raw_tokens.split(",") if token.strip()]


def is_control_plane_token_valid(presented_token: str, settings_obj) -> bool:
    """Return whether the presented bearer token matches a configured control-plane token."""
    if not presented_token:
        return False

    for configured_token in get_control_plane_tokens_from_settings(settings_obj):
        if secrets.compare_digest(presented_token.strip(), configured_token):
            return True
    return False


async def require_control_plane_access(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
):
    """Authorize WAF control-plane access via dashboard session or bearer service token."""
    session_payload = await get_current_user(request)
    if session_payload is not None:
        return {"auth_type": "session", "session": session_payload}

    if credentials and credentials.scheme.lower() == "bearer":
        if is_control_plane_token_valid(credentials.credentials, request.app.state.settings):
            return {"auth_type": "service_token"}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required for WAF control-plane access",
        headers={"WWW-Authenticate": "Bearer"},
    )
