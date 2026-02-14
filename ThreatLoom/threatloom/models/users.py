"""
User model with role-based access control fields.
"""
import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Enum, Boolean
from threatloom.database import Base


class UserRole(str, enum.Enum):
    VIEWER = "VIEWER"
    SOC_ANALYST = "SOC_ANALYST"
    ADMIN = "ADMIN"


class User(Base):
    """Platform user with RBAC."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)

    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=True)
    hashed_password = Column(String(255), nullable=False)

    role = Column(Enum(UserRole), nullable=False, default=UserRole.VIEWER)
    is_active = Column(Boolean, default=True)

    full_name = Column(String(128), nullable=True)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<User id={self.id} username={self.username} role={self.role}>"
