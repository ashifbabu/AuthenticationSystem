import json
import secrets
from typing import Dict, Optional
from urllib.parse import urlencode
from datetime import datetime, timedelta

import httpx
from fastapi import HTTPException, status

from app.core.config import settings
from app.core.enums import OAuthProvider
from app.schemas.oauth import OAuthUserInfo


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
    OAuthProvider.GITHUB: {
        "client_id": settings.GITHUB_CLIENT_ID,
        "client_secret": settings.GITHUB_CLIENT_SECRET,
        "auth_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "scope": "user:email",
    },
    OAuthProvider.LINKEDIN: {
        "client_id": settings.LINKEDIN_CLIENT_ID,
        "client_secret": settings.LINKEDIN_CLIENT_SECRET,
        "auth_url": "https://www.linkedin.com/oauth/v2/authorization",
        "token_url": "https://www.linkedin.com/oauth/v2/accessToken",
        "userinfo_url": "https://api.linkedin.com/v2/me",
        "scope": "r_liteprofile r_emailaddress",
    },
    OAuthProvider.TWITTER: {
        "client_id": settings.TWITTER_CLIENT_ID,
        "client_secret": settings.TWITTER_CLIENT_SECRET,
        "auth_url": "https://twitter.com/i/oauth2/authorize",
        "token_url": "https://api.twitter.com/2/oauth2/token",
        "userinfo_url": "https://api.twitter.com/2/users/me",
        "scope": "tweet.read users.read",
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
        
        token_data = response.json()
        
        # Ensure all required fields are present
        if not all(key in token_data for key in ["access_token", "expires_in"]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token response from provider",
            )
        
        # Add computed fields
        token_data["expires_at"] = datetime.utcnow() + timedelta(seconds=token_data["expires_in"])
        
        return token_data


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
    elif provider == OAuthProvider.GITHUB:
        headers["Accept"] = "application/vnd.github.v3+json"
    
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
            account_id=user_data["sub"],
            email=user_data["email"],
            first_name=user_data.get("given_name"),
            last_name=user_data.get("family_name"),
            raw_data=user_data
        )
    elif provider == OAuthProvider.FACEBOOK:
        return OAuthUserInfo(
            provider=provider,
            account_id=user_data["id"],
            email=user_data.get("email", ""),  # Facebook might not return email if not public
            first_name=user_data.get("first_name"),
            last_name=user_data.get("last_name"),
            raw_data=user_data
        )
    elif provider == OAuthProvider.GITHUB:
        # Get email from GitHub's email endpoint
        async with httpx.AsyncClient() as client:
            email_response = await client.get(
                "https://api.github.com/user/emails",
                headers=headers
            )
            if email_response.status_code == 200:
                emails = email_response.json()
                primary_email = next((email["email"] for email in emails if email["primary"]), emails[0]["email"])
            else:
                primary_email = user_data.get("email", "")
        
        # Split name into first and last name
        full_name = user_data.get("name", "").split(" ", 1)
        first_name = full_name[0] if full_name else None
        last_name = full_name[1] if len(full_name) > 1 else None
        
        return OAuthUserInfo(
            provider=provider,
            account_id=str(user_data["id"]),
            email=primary_email,
            first_name=first_name,
            last_name=last_name,
            raw_data=user_data
        )
    elif provider == OAuthProvider.LINKEDIN:
        return OAuthUserInfo(
            provider=provider,
            account_id=user_data["id"],
            email=user_data.get("emailAddress", ""),
            first_name=user_data.get("localizedFirstName"),
            last_name=user_data.get("localizedLastName"),
            raw_data=user_data,
        )
    elif provider == OAuthProvider.TWITTER:
        # Split name into first and last name
        full_name = user_data.get("data", {}).get("name", "").split(" ", 1)
        first_name = full_name[0] if full_name else None
        last_name = full_name[1] if len(full_name) > 1 else None
        
        return OAuthUserInfo(
            provider=provider,
            account_id=user_data["data"]["id"],
            email=user_data.get("data", {}).get("email", ""),
            first_name=first_name,
            last_name=last_name,
            raw_data=user_data,
        )
    
    # This should not happen due to the initial check, but just in case
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Unsupported OAuth provider: {provider}",
    )
