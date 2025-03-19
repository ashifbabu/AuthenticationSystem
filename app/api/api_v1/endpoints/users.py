from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.orm import Session
from typing import Any, List

from app.api.deps import get_db, get_current_user
from app.crud import user as user_crud
from app.crud import oauth_account as oauth_crud
from app.models.user import User
from app.schemas.user import UserUpdate, User as UserSchema
from app.schemas.oauth_account import OAuthAccount as OAuthAccountSchema
from app.schemas.message import Message
from app.core.security import verify_password

router = APIRouter()

@router.get("/me", response_model=UserSchema)
def read_current_user(
    current_user: User = Depends(get_current_user),
) -> Any:
    """Get current user."""
    return current_user

@router.put("/me", response_model=UserSchema)
def update_current_user(
    *,
    db: Session = Depends(get_db),
    user_in: UserUpdate,
    current_user: User = Depends(get_current_user),
) -> Any:
    """Update current user."""
    user = user_crud.update(db, db_obj=current_user, obj_in=user_in)
    return user

@router.delete("/me", response_model=Message)
def delete_current_user(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    password: str,
) -> Any:
    """Delete current user."""
    if not verify_password(password, current_user.hashed_password):
        raise HTTPException(
            status_code=400,
            detail="Incorrect password"
        )
    user_crud.delete(db, id=current_user.id)
    return {"message": "User deleted successfully"}

@router.get("/me/oauth-accounts", response_model=List[OAuthAccountSchema])
def read_oauth_accounts(
    current_user: User = Depends(get_current_user),
) -> Any:
    """Get current user's OAuth accounts."""
    return current_user.oauth_accounts

@router.delete("/oauth/{provider}", response_model=Message)
async def delete_oauth_account(
    provider: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Any:
    """Delete OAuth account."""
    oauth_account = oauth_crud.get_by_provider_and_user(
        db=db, provider=provider, user_id=current_user.id
    )
    if not oauth_account:
        raise HTTPException(status_code=404, detail="OAuth account not found")
    
    if oauth_crud.delete(db=db, id=oauth_account.id):
        return {"message": "OAuth account deleted successfully"}
    raise HTTPException(status_code=500, detail="Error deleting OAuth account") 