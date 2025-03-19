from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, ConfigDict

class OAuthAccountBase(BaseModel):
    """Base OAuth account schema."""
    provider: str
    account_id: str
    account_email: Optional[str] = None
    is_active: bool = True
    raw_data: Optional[Dict[str, Any]] = None

class OAuthAccountCreate(OAuthAccountBase):
    """OAuth account creation schema."""
    user_id: str
    access_token: str
    refresh_token: Optional[str] = None
    expires_at: Optional[datetime] = None

class OAuthAccountUpdate(BaseModel):
    """OAuth account update schema."""
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_at: Optional[datetime] = None
    is_active: Optional[bool] = None
    raw_data: Optional[Dict[str, Any]] = None

class OAuthAccountInDB(OAuthAccountBase):
    """OAuth account DB schema."""
    id: str
    user_id: str
    access_token: str
    refresh_token: Optional[str] = None
    expires_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class OAuthAccount(OAuthAccountInDB):
    """OAuth account schema."""
    pass 