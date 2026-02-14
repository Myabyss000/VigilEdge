"""
Role-Based Access Control.
"""
import logging
from functools import wraps
from typing import List, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from threatloom.database import get_db
from threatloom.models.users import User, UserRole
from threatloom.auth.jwt import decode_access_token, hash_password

logger = logging.getLogger("threatloom.auth")
security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Extract and validate the current user from JWT."""
    payload = decode_access_token(credentials.credentials)
    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    result = await db.execute(select(User).where(User.id == int(user_id)))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is deactivated")
    return user


def require_roles(allowed_roles: List[UserRole]):
    """Dependency factory: restrict endpoint to specified roles."""
    async def role_checker(user: User = Depends(get_current_user)):
        if user.role not in [r.value for r in allowed_roles] and user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user.role}' is not authorized for this action",
            )
        return user
    return role_checker


# Convenience dependencies
require_admin = require_roles([UserRole.ADMIN])
require_analyst = require_roles([UserRole.ADMIN, UserRole.SOC_ANALYST])
require_viewer = require_roles([UserRole.ADMIN, UserRole.SOC_ANALYST, UserRole.VIEWER])


async def create_default_admin(db: AsyncSession):
    """Create a default admin user if none exists."""
    from threatloom.config import settings

    result = await db.execute(select(User).where(User.role == UserRole.ADMIN))
    existing = result.scalar_one_or_none()

    if existing is None:
        admin = User(
            username=settings.DEFAULT_ADMIN_USER,
            hashed_password=hash_password(settings.DEFAULT_ADMIN_PASS),
            role=UserRole.ADMIN,
            full_name="System Administrator",
        )
        db.add(admin)
        await db.commit()
        logger.info(f"Default admin user '{settings.DEFAULT_ADMIN_USER}' created.")
    else:
        logger.info("Admin user already exists, skipping creation.")
