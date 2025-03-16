from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class LoginAttemptBase(BaseModel):
    """Base schema for login attempt."""
    email: str
    ip_address: str
    success: bool
    timestamp: datetime


class LoginAttempt(LoginAttemptBase):
    """Schema for login attempt."""
    id: str
    user_agent: Optional[str] = None

    class Config:
        orm_mode = True


class LoginAttemptCreate(BaseModel):
    """Schema for creating login attempt."""
    email: str
    ip_address: str
    user_agent: Optional[str] = None
    success: bool = False


class LoginAttemptStats(BaseModel):
    """Schema for login attempt statistics."""
    recent_attempts: int
    recent_failed_attempts: int
    is_locked: bool
    lockout_remaining: Optional[int] = None 