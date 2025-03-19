from enum import Enum
from typing import Dict, Any, Optional
from datetime import date, datetime

from pydantic import BaseModel, HttpUrl, Field
from app.core.enums import OAuthProvider


class OAuthRequest(BaseModel):
    redirect_uri: str
    state: Optional[str] = None


class OAuthCallback(BaseModel):
    code: str
    state: str
    redirect_uri: str


class OAuthUserInfo(BaseModel):
    """OAuth user information."""
    provider: OAuthProvider
    account_id: str
    email: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    raw_data: dict


class OAuthAccountBase(BaseModel):
    provider: OAuthProvider
    account_id: str
    account_email: str
    access_token: str
    refresh_token: Optional[str] = None
    expires_at: Optional[datetime] = None
    is_active: bool = True


class OAuthAccountCreate(OAuthAccountBase):
    user_id: str


class OAuthAccountUpdate(BaseModel):
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_at: Optional[datetime] = None
    is_active: Optional[bool] = None


class OAuthAccount(OAuthAccountBase):
    id: str
    user_id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
