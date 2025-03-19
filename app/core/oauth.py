from enum import Enum
from typing import Dict, Any
import httpx
from fastapi import HTTPException

from app.core.config import settings
from app.schemas.oauth import OAuthProvider, OAuthUserInfo

class OAuthProvider(str, Enum):
    """
    Supported OAuth providers.
    """
    GOOGLE = "google"
    GITHUB = "github"
    FACEBOOK = "facebook"

async def get_oauth_login_url(
    provider: OAuthProvider,
    redirect_uri: str,
    state: str
) -> str:
    """Get OAuth login URL for the specified provider."""
    if provider == OAuthProvider.GOOGLE:
        return (
            "https://accounts.google.com/o/oauth2/v2/auth"
            f"?client_id={settings.GOOGLE_CLIENT_ID}"
            "&response_type=code"
            "&scope=openid email profile"
            f"&redirect_uri={redirect_uri}"
            f"&state={state}"
        )
    elif provider == OAuthProvider.FACEBOOK:
        return (
            "https://www.facebook.com/v12.0/dialog/oauth"
            f"?client_id={settings.FACEBOOK_CLIENT_ID}"
            "&response_type=code"
            f"&redirect_uri={redirect_uri}"
            f"&state={state}"
            "&scope=email public_profile"
        )
    elif provider == OAuthProvider.GITHUB:
        return (
            "https://github.com/login/oauth/authorize"
            f"?client_id={settings.GITHUB_CLIENT_ID}"
            f"&redirect_uri={redirect_uri}"
            f"&state={state}"
            "&scope=user:email"
        )
    else:
        raise HTTPException(status_code=400, detail="Unsupported OAuth provider")

async def exchange_code_for_token(
    provider: OAuthProvider,
    code: str,
    redirect_uri: str
) -> Dict[str, Any]:
    """Exchange authorization code for access token."""
    async with httpx.AsyncClient() as client:
        if provider == OAuthProvider.GOOGLE:
            response = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "client_id": settings.GOOGLE_CLIENT_ID,
                    "client_secret": settings.GOOGLE_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "grant_type": "authorization_code"
                }
            )
        elif provider == OAuthProvider.FACEBOOK:
            response = await client.get(
                "https://graph.facebook.com/v12.0/oauth/access_token",
                params={
                    "client_id": settings.FACEBOOK_CLIENT_ID,
                    "client_secret": settings.FACEBOOK_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": redirect_uri
                }
            )
        elif provider == OAuthProvider.GITHUB:
            response = await client.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": settings.GITHUB_CLIENT_ID,
                    "client_secret": settings.GITHUB_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": redirect_uri
                },
                headers={"Accept": "application/json"}
            )
        else:
            raise HTTPException(status_code=400, detail="Unsupported OAuth provider")
        
        if response.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail="Failed to exchange authorization code for access token"
            )
        
        return response.json()

async def get_user_info(
    provider: OAuthProvider,
    access_token: str
) -> OAuthUserInfo:
    """Get user info from OAuth provider."""
    async with httpx.AsyncClient() as client:
        if provider == OAuthProvider.GOOGLE:
            response = await client.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            if response.status_code != 200:
                raise HTTPException(status_code=400, detail="Failed to get user info")
            
            data = response.json()
            return OAuthUserInfo(
                provider=provider,
                account_id=data["sub"],
                email=data["email"],
                first_name=data.get("given_name", ""),
                last_name=data.get("family_name", ""),
                raw_data=data
            )
        
        elif provider == OAuthProvider.FACEBOOK:
            response = await client.get(
                "https://graph.facebook.com/v12.0/me",
                params={
                    "fields": "id,email,first_name,last_name",
                    "access_token": access_token
                }
            )
            if response.status_code != 200:
                raise HTTPException(status_code=400, detail="Failed to get user info")
            
            data = response.json()
            return OAuthUserInfo(
                provider=provider,
                account_id=data["id"],
                email=data["email"],
                first_name=data.get("first_name", ""),
                last_name=data.get("last_name", ""),
                raw_data=data
            )
        
        elif provider == OAuthProvider.GITHUB:
            # Get user profile
            response = await client.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github.v3+json"
                }
            )
            if response.status_code != 200:
                raise HTTPException(status_code=400, detail="Failed to get user info")
            
            profile_data = response.json()
            
            # Get user emails
            response = await client.get(
                "https://api.github.com/user/emails",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github.v3+json"
                }
            )
            if response.status_code != 200:
                raise HTTPException(status_code=400, detail="Failed to get user emails")
            
            emails_data = response.json()
            primary_email = next(
                (email["email"] for email in emails_data if email["primary"]),
                None
            )
            
            if not primary_email:
                raise HTTPException(
                    status_code=400,
                    detail="No primary email found in GitHub account"
                )
            
            # Split name into first and last name
            name_parts = (profile_data.get("name") or "").split(maxsplit=1)
            first_name = name_parts[0] if name_parts else ""
            last_name = name_parts[1] if len(name_parts) > 1 else ""
            
            return OAuthUserInfo(
                provider=provider,
                account_id=str(profile_data["id"]),
                email=primary_email,
                first_name=first_name,
                last_name=last_name,
                raw_data={
                    "profile": profile_data,
                    "emails": emails_data
                }
            )
        
        else:
            raise HTTPException(status_code=400, detail="Unsupported OAuth provider") 