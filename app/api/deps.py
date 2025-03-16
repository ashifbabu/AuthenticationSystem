from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login"
)


def get_current_user():
    """
    Get the current authenticated user.
    This is a simplified placeholder for testing.
    """
    # In a real implementation, we would validate the token
    # For now, just return a test user
    return {"email": "test@example.com", "name": "Test User"}
