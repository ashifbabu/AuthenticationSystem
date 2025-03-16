import secrets
from typing import Any, List, Optional, Union

from pydantic import AnyHttpUrl, EmailStr, PostgresDsn, field_validator, model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Authentication System"
    ENVIRONMENT: str = "development"
    
    # SECURITY
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
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
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_DB: str = "auth_db"
    DATABASE_URI: Optional[str] = None

    @model_validator(mode="after")
    def assemble_db_connection(self) -> "Settings":
        if self.DATABASE_URI is None:
            self.DATABASE_URI = f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_SERVER}/{self.POSTGRES_DB}"
        return self

    # EMAIL
    EMAILS_ENABLED: bool = False
    EMAILS_FROM_NAME: str = PROJECT_NAME
    EMAILS_FROM_EMAIL: Optional[EmailStr] = None
    AWS_ACCESS_KEY: Optional[str] = None
    AWS_SECRET_KEY: Optional[str] = None
    AWS_REGION: Optional[str] = None

    # OAUTH
    GOOGLE_CLIENT_ID: Optional[str] = None
    GOOGLE_CLIENT_SECRET: Optional[str] = None
    FACEBOOK_CLIENT_ID: Optional[str] = None
    FACEBOOK_CLIENT_SECRET: Optional[str] = None
    OAUTH_REDIRECT_URL: Optional[str] = None
    FRONTEND_URL: Optional[str] = "http://localhost:3000"

    # Account lockout settings
    MAX_LOGIN_ATTEMPTS: int = 5  # Maximum number of login attempts before account lockout
    ACCOUNT_LOCKOUT_MINUTES: int = 30  # Duration of account lockout in minutes

    model_config = {
        "case_sensitive": True,
        "env_file": ".env",
    }


settings = Settings() 