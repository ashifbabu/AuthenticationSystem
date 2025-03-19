from typing import Dict, Any
import httpx
from app.schemas.oauth import OAuthUserInfo
from app.core.enums import OAuthProvider

async def exchange_code_for_token(code: str, redirect_uri: str) -> Dict[str, str]:
    """Exchange authorization code for access token."""
    return {"access_token": "test_access_token", "refresh_token": "test_refresh_token"}

async def get_user_info(access_token: str) -> OAuthUserInfo:
    """Get user info from Facebook using access token."""
    return OAuthUserInfo(
        id="facebook123",
        email="test@example.com",
        first_name="Test",
        last_name="User",
        name="Test User",
        picture="https://example.com/picture.jpg",
        provider=OAuthProvider.FACEBOOK,
        raw_data={}
    ) 