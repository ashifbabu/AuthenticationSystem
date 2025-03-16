from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.crud import user as user_crud

router = APIRouter()


@router.post("/login")
def login(
    db: Session = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    """
    OAuth2 compatible login endpoint.
    """
    # This is just a placeholder for testing
    return {"access_token": "test_token", "token_type": "bearer"} 