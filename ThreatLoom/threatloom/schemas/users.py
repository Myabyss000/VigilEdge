"""
Pydantic schemas for users and auth.
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class UserCreate(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: str = "VIEWER"


class UserUpdate(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


class UserResponse(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None

    model_config = {"from_attributes": True}


class TokenRequest(BaseModel):
    username: str
    password: str


class BootstrapStatusResponse(BaseModel):
    bootstrap_required: bool
    bootstrap_token_required: bool


class BootstrapAdminRequest(BaseModel):
    username: str
    password: str
    confirm_password: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    bootstrap_token: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class PasswordChange(BaseModel):
    current_password: str
    new_password: str

class PasswordResetRequest(BaseModel):
    username: str
    recovery_key: str
    new_password: str
    confirm_password: str
