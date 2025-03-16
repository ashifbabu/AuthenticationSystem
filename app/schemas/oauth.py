from enum import Enum
from typing import Dict, Optional

from pydantic import BaseModel, HttpUrl


class OAuthProvider(str, Enum):
    GOOGLE = "google"
    FACEBOOK = "facebook"


class OAuthRequest(BaseModel):
    provider: OAuthProvider
    redirect_uri: Optional[HttpUrl] = None


class OAuthCallback(BaseModel):
    provider: OAuthProvider
    code: str
    state: Optional[str] = None
    redirect_uri: Optional[HttpUrl] = None


class OAuthUserInfo(BaseModel):
    provider: OAuthProvider
    provider_user_id: str
    email: str
    first_name: str
    last_name: str
    picture_url: Optional[str] = None
    raw_data: Dict = {}
