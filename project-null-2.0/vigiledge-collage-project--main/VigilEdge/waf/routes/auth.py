"""
Authentication Routes
Handles login/logout functionality for the WAF dashboard.
"""

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

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Serve the login page."""
    # If already logged in, redirect to dashboard
    if request.cookies.get(COOKIE_NAME):
        return RedirectResponse(url="/admin/dashboard", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request})


@router.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...)
):
    """Handle login form submission."""
    # Get latest settings from app state (ensures password updates are seen immediately)
    app_settings = request.app.state.settings
    
    # Verify credentials
    # 1. Check against in-memory settings (fastest)
    if username == app_settings.admin_username and password == app_settings.admin_password:
        auth_success = True
    else:
        # 2. Fallback: Check config file directly (robust against reload/memory sync issues)
        # This handles cases where file updated but app state is stale
        auth_success = False
        try:
            import json
            from pathlib import Path
            settings_path = Path("config/waf_settings.json")
            if settings_path.exists():
                with open(settings_path, "r") as f:
                    file_settings = json.load(f)
                    file_auth = file_settings.get("authentication", {})
                    # Check if file has matching credentials
                    if (file_auth.get("admin_username") == username and 
                        file_auth.get("admin_password") == password):
                        auth_success = True
                        # Self-repair: Update memory to match file
                        app_settings.admin_password = password
                        print("Resync: Updated memory from file during login")
        except Exception as e:
            print(f"Auth fallback error: {e}")

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
    return templates.TemplateResponse("reset_password.html", {"request": request})

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
        settings_path = Path("config/waf_settings.json")
        if not settings_path.exists():
             return templates.TemplateResponse(
                "reset_password.html",
                {"request": request, "error": "System not initialized (Settings file missing)"}
            )
            
        with open(settings_path, "r") as f:
            file_settings = json.load(f)
            
        auth_config = file_settings.get("authentication", {})
        secret = auth_config.get("totp_secret")
        
        if not secret:
            return templates.TemplateResponse(
                "reset_password.html",
                {"request": request, "error": "2FA is not set up on this server. Run system setup first."}
            )
            
        totp = pyotp.TOTP(secret)
        if not totp.verify(totp_code.replace(" ", "")): # Handle spaces if user types them
            return templates.TemplateResponse(
                "reset_password.html",
                {"request": request, "error": "Invalid Authentication Code"}
            )
            
        # 3. Success - Update Password
        if "authentication" not in file_settings:
            file_settings["authentication"] = {}
            
        file_settings["authentication"]["admin_password"] = new_password
        
        with open(settings_path, "w") as f:
            json.dump(file_settings, f, indent=2)
            
        # Update memory state if available
        if hasattr(request.app.state, "settings"):
            request.app.state.settings.admin_password = new_password
            
        return RedirectResponse(url="/login?msg=password_reset", status_code=303)
        
    except Exception as e:
        print(f"Reset Error: {e}")
        return templates.TemplateResponse(
            "reset_password.html",
            {"request": request, "error": f"System Error: {str(e)}"}
        )

# --- 2FA Setup Routes (New) ---

@router.get("/auth/setup-2fa", response_class=HTMLResponse)
async def setup_2fa_page(request: Request):
    """Serve the 2FA setup page with a new QR code."""
    if not check_auth(request):
        return RedirectResponse(url="/login", status_code=302)
        
    # Generate new secret
    secret = pyotp.random_base32()
    
    # Generate QR URI
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name="Admin", 
        issuer_name="VigilEdge WAF"
    )
    
    # Generate Image to Base64
    img = qrcode.make(uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    qr_b64 = base64.b64encode(buffered.getvalue()).decode("utf-8")
    
    return templates.TemplateResponse("setup_2fa.html", {
        "request": request, 
        "secret": secret,
        "qr_b64": qr_b64
    })

@router.post("/auth/verify-2fa", response_class=HTMLResponse)
async def verify_2fa_setup(
    request: Request,
    secret: str = Form(...),
    code: str = Form(...)
):
    """Verify and save the new 2FA secret."""
    if not check_auth(request):
        return RedirectResponse(url="/login", status_code=302)
        
    totp = pyotp.TOTP(secret)
    if totp.verify(code.replace(" ", "")):
        # Valid! Save to settings
        try:
            settings_path = Path("config/waf_settings.json")
            if settings_path.exists():
                with open(settings_path, "r") as f:
                    settings = json.load(f)
            else:
                settings = {}
                
            if "authentication" not in settings:
                settings["authentication"] = {}
                
            settings["authentication"]["totp_secret"] = secret
            settings["authentication"]["2fa_enabled"] = True
            
            with open(settings_path, "w") as f:
                json.dump(settings, f, indent=2)
                
            return RedirectResponse(url="/admin/dashboard?msg=2fa_enabled", status_code=303)
            
        except Exception as e:
            return HTMLResponse(f"Error saving settings: {e}", status_code=500)
    else:
        return HTMLResponse("Invalid Code. Please try again.", status_code=400)

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
