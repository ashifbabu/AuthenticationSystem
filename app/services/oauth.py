import json
import secrets
from typing import Dict, Optional
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, status

from app.core.config import settings
from app.schemas.oauth import OAuthProvider, OAuthUserInfo


# OAuth configuration for providers
OAUTH_CONFIGS = {
    OAuthProvider.GOOGLE: {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "auth_url": "https://accounts.google.com/o/oauth2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://www.googleapis.com/oauth2/v3/userinfo",
        "scope": "openid email profile",
    },
    OAuthProvider.FACEBOOK: {
        "client_id": settings.FACEBOOK_CLIENT_ID,
        "client_secret": settings.FACEBOOK_CLIENT_SECRET,
        "auth_url": "https://www.facebook.com/v12.0/dialog/oauth",
        "token_url": "https://graph.facebook.com/v12.0/oauth/access_token",
        "userinfo_url": "https://graph.facebook.com/v12.0/me",
        "scope": "email public_profile",
        "userinfo_fields": "id,first_name,last_name,email,picture",
    },
}


def generate_oauth_state() -> str:
    """Generate a secure state token for OAuth requests."""
    return secrets.token_urlsafe(32)


def get_oauth_login_url(provider: OAuthProvider, redirect_uri: Optional[str] = None, state: Optional[str] = None) -> str:
    """Generate the OAuth login URL for the given provider."""
    config = OAUTH_CONFIGS.get(provider)
    
    if not config:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported OAuth provider: {provider}",
        )
    
    # Use the provided redirect_uri or fall back to the configured one
    oauth_redirect_uri = redirect_uri or settings.OAUTH_REDIRECT_URL
    
    # Generate a state token if none provided
    oauth_state = state or generate_oauth_state()
    
    # Build the authentication URL
    params = {
        "client_id": config["client_id"],
        "redirect_uri": oauth_redirect_uri,
        "response_type": "code",
        "scope": config["scope"],
        "state": oauth_state,
    }
    
    # Add extra parameters for specific providers
    if provider == OAuthProvider.FACEBOOK:
        params["auth_type"] = "rerequest"
    
    return f"{config['auth_url']}?{urlencode(params)}"


async def exchange_code_for_token(provider: OAuthProvider, code: str, redirect_uri: Optional[str] = None) -> Dict:
    """Exchange an authorization code for an access token."""
    config = OAUTH_CONFIGS.get(provider)
    
    if not config:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported OAuth provider: {provider}",
        )
    
    # Use the provided redirect_uri or fall back to the configured one
    oauth_redirect_uri = redirect_uri or settings.OAUTH_REDIRECT_URL
    
    # Prepare the token request data
    data = {
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "code": code,
        "redirect_uri": oauth_redirect_uri,
        "grant_type": "authorization_code",
    }
    
    # Make the token request
    async with httpx.AsyncClient() as client:
        response = await client.post(config["token_url"], data=data)
        
        if response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to exchange authorization code for token: {response.text}",
            )
        
        return response.json()


async def get_user_info(provider: OAuthProvider, token_data: Dict) -> OAuthUserInfo:
    """Retrieve user information from the OAuth provider."""
    config = OAUTH_CONFIGS.get(provider)
    
    if not config:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported OAuth provider: {provider}",
        )
    
    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Access token not found in token data",
        )
    
    # Set up the headers and parameters for the user info request
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {}
    
    # Add provider-specific parameters
    if provider == OAuthProvider.FACEBOOK:
        params["fields"] = config["userinfo_fields"]
    
    # Make the user info request
    async with httpx.AsyncClient() as client:
        response = await client.get(config["userinfo_url"], headers=headers, params=params)
        
        if response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to retrieve user information: {response.text}",
            )
        
        user_data = response.json()
    
    # Map provider-specific responses to the standard OAuthUserInfo format
    if provider == OAuthProvider.GOOGLE:
        return OAuthUserInfo(
            provider=provider,
            provider_user_id=user_data["sub"],
            email=user_data["email"],
            first_name=user_data.get("given_name", ""),
            last_name=user_data.get("family_name", ""),
            picture_url=user_data.get("picture"),
            raw_data=user_data,
        )
    elif provider == OAuthProvider.FACEBOOK:
        return OAuthUserInfo(
            provider=provider,
            provider_user_id=user_data["id"],
            email=user_data.get("email", ""),  # Facebook might not return email if not public
            first_name=user_data.get("first_name", ""),
            last_name=user_data.get("last_name", ""),
            picture_url=user_data.get("picture", {}).get("data", {}).get("url") if "picture" in user_data else None,
            raw_data=user_data,
        )
    
    # This should not happen due to the initial check, but just in case
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Unsupported OAuth provider: {provider}",
    )
