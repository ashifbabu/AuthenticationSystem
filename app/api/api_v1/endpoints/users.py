from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.orm import Session
from typing import Any, List

from app.api.deps import get_db, get_current_user, get_current_active_user, get_current_verified_user
from app.crud import user as user_crud
from app.crud.oauth_account import oauth_crud
from app.models.user import User
from app.schemas.user import UserUpdate, User as UserSchema
from app.schemas.oauth import OAuthAccount
from app.schemas.message import Message
from app.core.security import verify_password
from app.core.enums import OAuthProvider

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

@router.delete("/me", status_code=204)
def delete_account(
    password: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    """Delete current user account."""
    # Verify password
    if not verify_password(password, current_user.hashed_password):
        raise HTTPException(
            status_code=400,
            detail="Incorrect password"
        )
    
    try:
        # Delete user
        user_crud.remove(db=db, id=current_user.id)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete account: {str(e)}"
        )
    
    return None

@router.get("/me/oauth-accounts", response_model=List[OAuthAccount])
def read_oauth_accounts(
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> Any:
    """Get current user's OAuth accounts."""
    return oauth_crud.get_by_user_id(db=db, user_id=current_user.id)

@router.delete("/me/oauth-accounts/{provider}", response_model=Message)
async def delete_oauth_account(
    provider: OAuthProvider,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Any:
    """Delete OAuth account."""
    try:
        oauth_account = oauth_crud.get_by_provider_and_user_id(
            db=db, provider=provider, user_id=current_user.id
        )
        if not oauth_account:
            raise HTTPException(status_code=404, detail="OAuth account not found")
        
        oauth_crud.remove(db=db, id=oauth_account.id)
        return {"message": "OAuth account deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 