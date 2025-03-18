from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status, Body
from sqlalchemy.orm import Session

from app.api.dependencies.auth import get_current_active_user, get_current_verified_user
from app.db.session import get_db
from app.crud import user as user_crud
from app.core.security import verify_password
from app.models.oauth import OAuthProvider
from app.models.user import User
from app.schemas.oauth import OAuthUserInfo
from app.schemas.user import User as UserSchema, UserUpdate


router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserSchema)
def read_current_user(
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Get current user information.
    """
    return current_user


@router.put("/me", response_model=UserSchema)
def update_current_user(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
    user_in: UserUpdate,
) -> Any:
    """
    Update current user information.
    """
    user = user_crud.update(db, db_obj=current_user, obj_in=user_in)
    return user


@router.get("/me/oauth-accounts", response_model=List[OAuthUserInfo])
def read_oauth_accounts(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Get current user's connected OAuth accounts.
    """
    # This is a simplified approach. In a real application, you would
    # store more information about the OAuth accounts in the database.
    # For now, we'll just return the provider and provider_user_id.
    
    # Get all OAuth accounts for the current user
    oauth_accounts = current_user.oauth_accounts
    
    # Convert to OAuthUserInfo objects
    result = []
    for account in oauth_accounts:
        result.append(
            OAuthUserInfo(
                provider=account.provider,
                provider_user_id=account.provider_user_id,
                email=current_user.email,
                first_name=current_user.first_name,
                last_name=current_user.last_name,
                picture_url=None,  # We don't store this information in our current model
                raw_data={},
            )
        )
    
    return result


@router.delete("/me/oauth-accounts/{provider}", response_model=UserSchema)
def delete_oauth_account(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
    provider: OAuthProvider,
) -> Any:
    """
    Delete an OAuth account for the current user.
    """
    # Check if the user has the OAuth account
    oauth_account = user_crud.get_by_user_id_and_provider(
        db, user_id=current_user.id, provider=provider
    )
    
    if not oauth_account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OAuth account for provider {provider} not found",
        )
    
    # Check if the user has a password - at least one authentication method is required
    if not current_user.password_hash and len(current_user.oauth_accounts) == 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete the only authentication method",
        )
    
    # Delete the OAuth account
    user_crud.delete(db, oauth_account_id=oauth_account.id)
    
    return current_user


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
def delete_current_user(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
    password: str = Body(...),
) -> None:
    """
    Delete current user.
    """
    if not verify_password(password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect password",
        )
    
    user_crud.delete(db, id=current_user.id)
    return None 