from enum import Enum
from typing import Dict, Optional
from datetime import date

from pydantic import BaseModel, HttpUrl
from app.core.enums import OAuthProvider


class OAuthRequest(BaseModel):
    redirect_uri: str
    state: Optional[str] = None


class OAuthCallback(BaseModel):
    code: str
    state: str
    redirect_uri: str


class OAuthUserInfo(BaseModel):
    provider: OAuthProvider
    provider_user_id: str
    email: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    picture_url: Optional[str] = None
    gender: Optional[str] = None
    date_of_birth: Optional[date] = None
    raw_data: Optional[Dict] = None
