"""
User management and authentication API endpoints.
"""
from datetime import datetime
import secrets
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from threatloom.database import get_db
from threatloom.models.users import User, UserRole
from threatloom.schemas.users import (
    UserCreate, UserUpdate, UserResponse, TokenRequest, TokenResponse, PasswordChange,
    BootstrapStatusResponse, BootstrapAdminRequest, PasswordResetRequest
)
from threatloom.auth.jwt import hash_password, verify_password, create_access_token
from threatloom.auth.rbac import require_admin, get_current_user
from threatloom.auth.audit import record_audit
from threatloom.config import settings

router = APIRouter()


async def _admin_exists(db: AsyncSession) -> bool:
    result = await db.execute(select(User.id).where(User.role == UserRole.ADMIN).limit(1))
    return result.scalar_one_or_none() is not None


def _bootstrap_token_required() -> bool:
    return bool((settings.BOOTSTRAP_ADMIN_TOKEN or "").strip())


def _validate_bootstrap_token(presented_token: str | None) -> bool:
    configured = (settings.BOOTSTRAP_ADMIN_TOKEN or "").strip()
    if not configured:
        return True
    if not presented_token:
        return False
    return secrets.compare_digest(configured, presented_token.strip())


@router.get("/bootstrap/status", response_model=BootstrapStatusResponse)
async def bootstrap_status(db: AsyncSession = Depends(get_db)):
    """Return whether ThreatLoom still requires first-run admin bootstrap."""
    admin_exists = await _admin_exists(db)
    return BootstrapStatusResponse(
        bootstrap_required=not admin_exists,
        bootstrap_token_required=_bootstrap_token_required(),
    )


@router.post("/bootstrap", response_model=TokenResponse)
async def bootstrap_admin(payload: BootstrapAdminRequest, db: AsyncSession = Depends(get_db)):
    """Create the initial admin user exactly once during first-run setup."""
    if await _admin_exists(db):
        raise HTTPException(status_code=409, detail="ThreatLoom admin bootstrap is already complete")

    username = payload.username.strip()
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(payload.password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters")
    if payload.password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    if _bootstrap_token_required() and not _validate_bootstrap_token(payload.bootstrap_token):
        raise HTTPException(status_code=403, detail="Invalid bootstrap token")

    existing = await db.execute(select(User).where(User.username == username))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already exists")

    user = User(
        username=username,
        hashed_password=hash_password(payload.password),
        email=payload.email,
        full_name=payload.full_name,
        role=UserRole.ADMIN,
        is_active=True,
        last_login=datetime.utcnow(),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    token = create_access_token({"sub": str(user.id), "role": user.role.value})
    return TokenResponse(
        access_token=token,
        expires_in=settings.JWT_EXPIRY_MINUTES * 60,
        user=UserResponse.model_validate(user),
    )


@router.post("/login", response_model=TokenResponse)
async def login(payload: TokenRequest, db: AsyncSession = Depends(get_db)):
    """Authenticate and receive JWT token."""
    if not await _admin_exists(db):
        raise HTTPException(status_code=403, detail="ThreatLoom bootstrap is required before login")

    result = await db.execute(select(User).where(User.username == payload.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account deactivated")

    token = create_access_token({"sub": str(user.id), "role": user.role.value})

    user.last_login = datetime.utcnow()
    await db.commit()

    return TokenResponse(
        access_token=token,
        expires_in=settings.JWT_EXPIRY_MINUTES * 60,
        user=UserResponse.model_validate(user),
    )


@router.get("/me", response_model=UserResponse)
async def get_me(user: User = Depends(get_current_user)):
    """Get current user info."""
    return user


@router.put("/me/password")
async def change_password(
    payload: PasswordChange,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Change own password."""
    if not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password incorrect")

    user.hashed_password = hash_password(payload.new_password)
    await record_audit(
        db, action="user.password_change", user_id=user.id, username=user.username,
        resource_type="user", resource_id=user.id,
    )
    await db.commit()
    return {"status": "password_changed"}


@router.get("/", response_model=List[UserResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """List all users (admin only)."""
    result = await db.execute(select(User).order_by(User.created_at))
    return result.scalars().all()


@router.post("/", response_model=UserResponse)
async def create_user(
    payload: UserCreate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Create a new user (admin only)."""
    # Check duplicate
    existing = await db.execute(select(User).where(User.username == payload.username))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already exists")

    user = User(
        username=payload.username,
        hashed_password=hash_password(payload.password),
        email=payload.email,
        full_name=payload.full_name,
        role=UserRole(payload.role),
    )
    db.add(user)

    await record_audit(
        db, action="user.create", user_id=admin.id, username=admin.username,
        resource_type="user", resource_id=payload.username,
    )

    await db.commit()
    return user


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    payload: UserUpdate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Update a user (admin only)."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if payload.email is not None:
        user.email = payload.email
    if payload.full_name is not None:
        user.full_name = payload.full_name
    if payload.role is not None:
        user.role = UserRole(payload.role)
    if payload.is_active is not None:
        user.is_active = payload.is_active

    await record_audit(
        db, action="user.update", user_id=admin.id, username=admin.username,
        resource_type="user", resource_id=user_id,
    )

    await db.commit()
    return user

@router.post("/reset-password")
async def reset_password(payload: PasswordResetRequest, db: AsyncSession = Depends(get_db)):
    """Reset a user's password using the server-side recovery key."""
    if not settings.PASSWORD_RECOVERY_KEY:
        raise HTTPException(status_code=500, detail="Password recovery not configured on server")
        
    if not secrets.compare_digest(payload.recovery_key, settings.PASSWORD_RECOVERY_KEY):
        raise HTTPException(status_code=401, detail="Invalid recovery key")
        
    if payload.new_password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
        
    # Get user
    result = await db.execute(select(User).where(User.username == payload.username))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    user.hashed_password = hash_password(payload.new_password)
    
    await record_audit(
        db, action="auth.password_reset", user_id=user.id, username=user.username,
        resource_type="auth", resource_id=user.id,
    )
    
    await db.commit()
    return {"detail": "Password reset successful"}
