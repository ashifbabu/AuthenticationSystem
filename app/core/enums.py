from enum import Enum
from typing import Dict, Any


class OAuthProvider(str, Enum):
    """OAuth provider enumeration."""
    GOOGLE = "google"
    FACEBOOK = "facebook"
    GITHUB = "github"
    LINKEDIN = "linkedin"
    TWITTER = "twitter"


# OAuth provider configurations
OAUTH_CONFIGS: Dict[OAuthProvider, Dict[str, Any]] = {
    OAuthProvider.GOOGLE: {
        "client_id": "GOOGLE_CLIENT_ID",
        "client_secret": "GOOGLE_CLIENT_SECRET",
        "auth_url": "https://accounts.google.com/o/oauth2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://www.googleapis.com/oauth2/v3/userinfo",
        "scope": "openid email profile",
    },
    OAuthProvider.FACEBOOK: {
        "client_id": "FACEBOOK_CLIENT_ID",
        "client_secret": "FACEBOOK_CLIENT_SECRET",
        "auth_url": "https://www.facebook.com/v12.0/dialog/oauth",
        "token_url": "https://graph.facebook.com/v12.0/oauth/access_token",
        "userinfo_url": "https://graph.facebook.com/v12.0/me",
        "scope": "email public_profile",
        "userinfo_fields": "id,first_name,last_name,email,picture",
    },
    OAuthProvider.GITHUB: {
        "client_id": "GITHUB_CLIENT_ID",
        "client_secret": "GITHUB_CLIENT_SECRET",
        "auth_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "scope": "user:email",
    },
    OAuthProvider.LINKEDIN: {
        "client_id": "LINKEDIN_CLIENT_ID",
        "client_secret": "LINKEDIN_CLIENT_SECRET",
        "auth_url": "https://www.linkedin.com/oauth/v2/authorization",
        "token_url": "https://www.linkedin.com/oauth/v2/accessToken",
        "userinfo_url": "https://api.linkedin.com/v2/me",
        "scope": "r_liteprofile r_emailaddress",
    },
    OAuthProvider.TWITTER: {
        "client_id": "TWITTER_CLIENT_ID",
        "client_secret": "TWITTER_CLIENT_SECRET",
        "auth_url": "https://twitter.com/i/oauth2/authorize",
        "token_url": "https://api.twitter.com/2/oauth2/token",
        "userinfo_url": "https://api.twitter.com/2/users/me",
        "scope": "tweet.read users.read",
    },
} 