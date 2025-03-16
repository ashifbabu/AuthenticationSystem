from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.crud import user as user_crud

router = APIRouter()


@router.get("/me")
def read_users_me():
    """
    Get current user.
    """
    # This is just a placeholder for testing
    return {"email": "test@example.com", "name": "Test User"} 