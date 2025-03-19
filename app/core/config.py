import secrets
from typing import Any, List, Optional, Union

from pydantic import AnyHttpUrl, EmailStr, PostgresDsn, field_validator, model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Authentication System"
    ENVIRONMENT: str = "development"
    VERSION: str = "1.0.0"
    
    # SECURITY
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    ALGORITHM: str = "HS256"
    
    # CORS
    CORS_ORIGINS: List[AnyHttpUrl] = []

    @field_validator("CORS_ORIGINS", mode="before")
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    # DATABASE
    SQLALCHEMY_DATABASE_URL: str = "sqlite:///:memory:"

    # EMAIL
    EMAILS_ENABLED: bool = False
    EMAILS_FROM_NAME: Optional[str] = None
    EMAILS_FROM_EMAIL: Optional[str] = None
    SMTP_TLS: bool = True
    SMTP_PORT: Optional[int] = None
    SMTP_HOST: Optional[str] = None
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None

    # OAUTH
    GOOGLE_CLIENT_ID: str = "test-google-client-id"
    GOOGLE_CLIENT_SECRET: str = "test-google-client-secret"
    FACEBOOK_CLIENT_ID: str = "test-facebook-client-id"
    FACEBOOK_CLIENT_SECRET: str = "test-facebook-client-secret"
    GITHUB_CLIENT_ID: str = "test-github-client-id"
    GITHUB_CLIENT_SECRET: str = "test-github-client-secret"
    LINKEDIN_CLIENT_ID: str = "test-linkedin-client-id"
    LINKEDIN_CLIENT_SECRET: str = "test-linkedin-client-secret"
    TWITTER_CLIENT_ID: str = "test-twitter-client-id"
    TWITTER_CLIENT_SECRET: str = "test-twitter-client-secret"
    OAUTH_REDIRECT_URL: str = "http://localhost:8000/api/v1/auth/oauth/callback"
    FRONTEND_URL: str = "http://localhost:3000"
    OAUTH_REDIRECT_URI: str = "http://localhost:3000/oauth/callback"

    # OAuth provider settings
    OAUTH_PROVIDERS: List[str] = ["google", "facebook", "github", "linkedin", "twitter"]
    OAUTH_STATE_EXPIRE_MINUTES: int = 10
    OAUTH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days

    # Account lockout settings
    MAX_LOGIN_ATTEMPTS: int = 10  # Increase max attempts for tests
    ACCOUNT_LOCKOUT_MINUTES: int = 1  # Reduce lockout time for tests

    # Security
    VERIFY_EMAIL: bool = False  # Disable email verification for tests
    ALLOW_REGISTRATION: bool = True
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_MAX_LENGTH: int = 50
    PASSWORD_REGEX: str = r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$"

    # Superuser
    FIRST_SUPERUSER_EMAIL: str = "admin@example.com"
    FIRST_SUPERUSER_PASSWORD: str = "Admin123!@#"

    model_config = {
        "case_sensitive": True,
        "env_file": ".env",
    }


settings = Settings() 